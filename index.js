require('dotenv').config()
const express = require('express')
const bodyParser = require('body-parser')
const base64 = require('base-64');
const helmet = require('helmet')
const crypto = require('crypto')
const createError = require('http-errors');
const { log } = require('console')
const app = express()
const axios = require('axios');
const port = process.env.PORT || 4000
const { getChatbotToken } = require('./chatbotToken');


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
var token = ""
var accountId = ""

app.use(helmet(headers));

app.use(bodyParser.json())

app.get('/', (req, res) => {
  res.send('Welcome to this demo bot')
})

app.get('/authorize', async (req, res) => {
  try {
    const { zoom_client_id, zoom_client_secret, zoom_bot_jid, redirect_uri } = process.env;
    const credentials = `${zoom_client_id}:${zoom_client_secret}`;
    const encodedCredentials = Buffer.from(credentials).toString('base64');
    
    const response = await axios.post(
      `https://zoom.us/oauth/token`,
      null,
      {
        params: {
          grant_type: 'authorization_code',
          code: req.query.code,
          redirect_uri: redirect_uri
        },
        headers: {
          Authorization: `Basic ${encodedCredentials}`
        }
      }
    );

    const { data } = response;
    const token = data.access_token;
    
    res.redirect(`https://zoom.us/launch/chat?jid=robot_${zoom_bot_jid}`);
  } catch (error) {
    console.log('Error getting access token', error);
    res.status(500).send('Error getting access token');
  }
});


app.get('/zoomverify/verifyzoom.html', (req, res) => {
  res.send(process.env.zoom_verification_code)
})

app.get('/proxy', (req, res) => {
  res.sendFile(__dirname + '/apiresponse.html')
})

const WEBVIEW_HTML_PATH = __dirname + '/webview.html';
const SEND_PREVIEW_HTML_PATH = __dirname + '/SendPreview.html';

const routeHandlers = {
  'SendMessage': (req, res) => {
    res.sendFile(WEBVIEW_HTML_PATH);
  },
  'SendMessagePreview': (req, res) => {
    res.sendFile(SEND_PREVIEW_HTML_PATH);
  },
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

app.post('/new_vote', async (req, res) => {
  accountId=req.body.payload.accountId
  console.log("/new_vote api -- message sent from zoom", req)
  console.log("/new_vote api -- auth header", req.headers.authorization)
  if (req.headers.authorization === process.env.zoom_verification_token) {
    try {
      const chatbotToken = await getChatbotToken();
      const recordings = await getRecordings();
      const chatBody = generateChatBody(recordings, req.body.payload);
      await sendChat(chatBody, chatbotToken);
      console.log("/new_vote api -- chatbot token -- ", chatbotToken)
      res.status(200).send();
    } catch (error) {
      console.log('Error occurred:', error);
      res.status(500).send('/new_vote api -- Internal Server Error');
    }
  } else {
    console.log("/new_vote api -- random testing")
    res.status(401).send('/new_vote api -- Unauthorized request to Zoom Chatbot.');
  }

  async function getRecordings() {
    const response = await axios.get(`https://api.zoom.us/v2/users/me/recordings?from=2023-04-11&to=2023-05-10`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    if (response.status !== 200 || response.data.errors) {
      throw new Error('Error getting recordings from Zoom');
    }
    return response.data;
  }

  function generateChatBody(recordings, payload) {
    console.log('recordings', recordings);
  
    const chatBody = {
      robot_jid: process.env.zoom_bot_jid,
      to_jid: payload.toJid,
      user_jid: payload.userJid,
      account_id: accountId,
      visible_to_user: true,
      content: {
        head: {
          text: 'Your recordings:',
          sub_head: {
            text: 'Sent by ' + payload.userName
          }
        },
        body: recordings.meetings.flatMap(meeting => ([
          {
            type: 'message',
            text: 'Meeting ID: ' + meeting.id
          },
          {
            type: 'message',
            text: 'Meeting UUID: ' + meeting.uuid
          },
          {
            type: 'message',
            text: meeting.topic,
            link: meeting.share_url
          }
        ]))
      }
    };
  
    return chatBody;
  }
  
  

  async function sendChat(chatBody, chatbotToken) {
    const response = await axios({
      url: 'https://api.zoom.us/v2/im/chat/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${chatbotToken}`
      },
      data: chatBody
    });
    console.log('send chat response status', response.status)
    if (response.status >= 400) {
      throw new Error('Error sending chat');
    }
  }
});
app.listen(port, () => console.log(`The recordings bot is listnening on ${port}!`))