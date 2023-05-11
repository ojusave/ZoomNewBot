require('dotenv').config()
const express = require('express')
const bodyParser = require('body-parser')
const base64 = require('base-64');
const helmet = require('helmet')
const crypto = require('crypto')
const createError = require('http-errors');
const { log, error } = require('console')
const app = express()
const axios = require('axios');
const port = process.env.PORT || 4000
const { getChatbotToken } = require('./chatbotToken');
const { zoomOAuth } = require("./zoomOAuth");
const { getRecordings } = require("./getRecordings");
const { generateChatBody, sendChat } = require("./generateChatBody");
const e = require('express');


/*  Middleware */
const headers = {
  frameguard: {
    action: 'sameorigin',
  },
  hsts: {
    maxAge: 31536000,
  },
  referrerPolicy: 'same-origin',
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: {
    directives: {
      'default-src': 'self',
      styleSrc: ["'self'"],
      imgSrc: ["'self'", `*`],
      'connect-src': 'self',
      'base-uri': 'self',
      'form-action': 'self',
    },
  },
};

var appContextCache = {}
var accountId = "";
exports.accountId = accountId;

app.use(helmet(headers));

app.use(bodyParser.json())

app.get('/', (req, res) => {
  res.send('Welcome to this demo bot')
})

app.get('/authorize', zoomOAuth);

app.get('/zoomverify/verifyzoom.html', (req, res) => {
  res.send(process.env.zoom_verification_code)
})

const WEBVIEW_HTML_PATH = __dirname + '/webview.html';
const SEND_PREVIEW_HTML_PATH = __dirname + '/SendPreview.html';
const RECORDINGS_FILE = __dirname + '/recordings.html';

const routeHandlers = {
  'SendMessage': (req, res) => {
    res.sendFile(WEBVIEW_HTML_PATH);
  },
  'SendMessagePreview': (req, res) => {
    res.sendFile(SEND_PREVIEW_HTML_PATH);
  },
  'findrecordings': (req, res) => {
    res.sendFile(RECORDINGS_FILE);
  }
};

app.get('/webview.html', (req, res) => {
  const appContext = getAppContext(req.get('x-zoom-app-context'), process.env.zoom_client_secret);
  appContextCache = appContext;
  console.log("/webview api --- app context - ", appContext);
  const { sid } = appContext;
  console.log('/webview api --- SID ', sid);
  req.app.locals.sid = sid;

  res.set({
    "Content-Security-Policy": "default-src 'self' * 'nonce-rAnd0m'",
    "X-Frame-Options": "SAMEORIGIN",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "origin"
  });

  res.cookie("zoom_client_secret", process.env.zoom_client_secret);

  const routeHandler = routeHandlers[appContext.actid];
  if (routeHandler) {
    routeHandler(req, res);
  } else {
    res.sendStatus(404);
  }
});

app.get('/meetingIds', async (req, res) => {
  const { from, to } = req.query;
  console.log("from = ", from, " , to = ", to);
  // Validate the date format
  const dateFormat = /^\d{4}-\d{2}-\d{2}$/;
  if (!dateFormat.test(from) || !dateFormat.test(to)) {
    return res.status(400).json({ error: 'Invalid date format. Please provide dates in yyyy-mm-dd format.' });
  }

    var recordings = await getRecordings(from, to);


    console.log("recordings", recordings)

    const meetingIds = recordings.meetings.flatMap(meeting => ([
      meeting.id
    ]));

    res.json(meetingIds);

});
app.get('/recordings.js', (req, res) => {
  res.sendFile(__dirname + '/recordings.js');
})

app.get('/sdk.js', (req, res) => {
  res.sendFile(__dirname + '/sdk.js');
})

app.get('/card.js', (req, res) => {
  res.sendFile(__dirname + '/card.js');
})

app.get('/crypto-js.js', (req, res) => {
  res.sendFile(__dirname + '/crypto-js.js');
})
  ;

app.post('/chat', async (req, res) => {
  const chatbotToken = await getChatbotToken();
  const input = req.body.input;
  const reqBody = {
    robot_jid: process.env.zoom_bot_jid,
    to_jid: `${appContextCache.uid}@xmpp.zoom.us/${appContextCache.sid}`,
    account_id: accountId,
    user_jid: `${appContextCache.uid}@xmpp.zoom.us`,
    is_markdown_support: true,
    content: {
      settings: {
        default_sidebar_color: "#357B2A"
      },
      body: [
        {
          type: "message",
          text: input
        }
      ]
    }
  };

  try {
    const response = await axios({
      method: 'POST',
      url: 'https://api.zoom.us/v2/im/chat/messages',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${chatbotToken}`
      },
      data: reqBody
    });

    console.log("response for zoom api call", response.data);
    res.status(200).send(response.data);
  } catch (error) {
    console.log('Error sending chat.', error);
    res.status(500).send(error.message);
  }
});
/**
 * Decodes, parses and decrypts the x-zoom-app-context header
 * @see https://marketplace.zoom.us/docs/beta-docs/zoom-apps/zoomappcontext#decrypting-the-header-value
 * @param {String} header - Encoded Zoom App Context header
 * @param {String} [secret=''] - Client Secret for the Zoom App
 * @return {JSON|Error} Decrypted Zoom App Context or Error
 */
function getAppContext(header, secret = '') {
  console.log('getAppContext -- context header', header)
  if (!header || typeof header !== 'string') {
    throw createError(500, 'context header must be a valid string');
  }

  console.log('getAppContext -- context header secret', secret)

  const key = secret;

  // Decode and parse context
  const { iv, aad, cipherText, tag } = unpack(header);

  // Create sha256 hash from Client Secret (key)
  const hash = crypto.createHash('sha256').update(key).digest();

  // return decrypted context
  return decrypt(cipherText, hash, iv, aad, tag);
}

/*
**
 * Decode and parse a base64 encoded Zoom App Context
 * @param {String} ctx - Encoded Zoom App Context
 * @return {Object} Decoded Zoom App Context object
 */
function unpack(ctx) {
  // Decode base64
  let buf = Buffer.from(ctx, 'base64');

  // Get iv length (1 byte)
  const ivLength = buf.readUInt8();
  buf = buf.slice(1);

  // Get iv
  const iv = buf.slice(0, ivLength);
  buf = buf.slice(ivLength);

  // Get aad length (2 bytes)
  const aadLength = buf.readUInt16LE();
  buf = buf.slice(2);

  // Get aad
  const aad = buf.slice(0, aadLength);
  buf = buf.slice(aadLength);

  // Get cipher length (4 bytes)
  const cipherLength = buf.readInt32LE();
  buf = buf.slice(4);

  // Get cipherText
  const cipherText = buf.slice(0, cipherLength);

  // Get tag
  const tag = buf.slice(cipherLength);

  return {
    iv,
    aad,
    cipherText,
    tag,
  };
}

/**
 * Decrypts cipherText from a decoded Zoom App Context object
 * @param {Buffer} cipherText - Data to decrypt
 * @param {Buffer} hash - sha256 hash of the Client Secret
 * @param {Buffer} iv - Initialization Vector for cipherText
 * @param {Buffer} aad - Additional Auth Data for cipher
 * @param {Buffer} tag - cipherText auth tag
 * @return {JSON|Error} Decrypted JSON obj from cipherText or Error
 */
function decrypt(cipherText, hash, iv, aad, tag) {
  // AES/GCM decryption
  const decipher = crypto
    .createDecipheriv('aes-256-gcm', hash, iv)
    .setAAD(aad)
    .setAuthTag(tag)
    .setAutoPadding(false);

  const update = decipher.update(cipherText, 'hex', 'utf-8');
  const final = decipher.final('utf-8');

  const decrypted = update + final;

  return JSON.parse(decrypted);
}

app.post('/:command', async (req, res) => {
  const command = req.params.command; // Extract the command from the route parameter

  var from = '2023-04-10'
  var to = '2023-05-10'
  if (req.headers.authorization === process.env.zoom_verification_token) {
    try {
      const chatbotToken = await getChatbotToken();
      const recordings = await getRecordings(from, to);
      const chatBody = generateChatBody(recordings, req.body.payload);
      await sendChat(chatBody, chatbotToken);
      res.status(200).send();
    } catch (error) {
      console.log('Error occurred:', error);
      res.status(500).send(`/${command} api -- Internal Server Error`);
    }
  } else {
    res.status(401).send(`/${command} api -- Unauthorized request to Zoom Chatbot.`);
  }


});

app.listen(port, () => console.log(`The recordings bot is listnening on ${port}!`))