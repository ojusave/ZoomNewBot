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

//const simpleCacheByUid = {};
var appContextCache = {}
var token = ""

app.use(helmet(headers));

app.use(bodyParser.json())

app.get('/', (req, res) => {
  res.send('Welcome to this demo bot')
})

app.get('/authorize', async (req, res) => {
  const credentials = `${process.env.zoom_client_id}:${process.env.zoom_client_secret}`;
  const encodedCredentials = base64.encode(credentials);

  try {
    const response = await axios({
      method: 'POST',
      url: 'https://zoom.us/oauth/token',
      headers: {
        'Authorization': `Basic ${encodedCredentials}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      data: 'grant_type=client_credentials'
    });

    const data = response.data;
    token = data.access_token;
    res.redirect(`https://zoom.us/launch/chat?jid=robot_${process.env.zoom_bot_jid}`);
  } catch (error) {
    console.log("Error getting access token", error);
    res.status(500).send('Error getting access token');
  }
});


app.get('/zoomverify/verifyzoom.html', (req, res) => {
  res.send(process.env.zoom_verification_code)
})

app.get('/webview.html', (req, res) => {
  var appContext = getAppContext(req.get('x-zoom-app-context'), process.env.zoom_client_secret)

  appContextCache = appContext

  console.log("/webview api --- app context - ", appContext)
  const { sid } = appContext
  console.log('/webview api --- SID ', sid)
  req.app.locals.sid = sid
  res.setHeader("Content-Security-Policy", "default-src 'self' * 'nonce-rAnd0m'")
  res.setHeader("X-Frame-Options", "SAMEORIGIN")
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
  res.setHeader("X-Content-Type-Options", "nosniff")
  res.setHeader("Referrer-Policy", "origin")
  res.cookie("zoom_client_secret", process.env.zoom_client_secret)
  if (appContext.actid === 'SendMessage') {
    res.sendFile(__dirname + '/webview.html');
  }
  else if (appContext.actid === "SendMessagePreview") {
    res.sendFile(__dirname + '/SendPreview.html');
  }
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
  console.log("/chat api -- appContextCache --", appContextCache);
  var input = req.body.input
  const reqBody = {
    'robot_jid': process.env.zoom_bot_jid,
    'to_jid': appContextCache.uid+"@xmpp.zoom.us"+"/"+appContextCache.sid,
    'account_id': process.env.zoom_account_id,
    'user_jid': appContextCache.uid+"@xmpp.zoom.us",
    "is_markdown_support": true,
    "content": {
      "settings": {
        "default_sidebar_color": "#357B2A"
      },
      "body": [
        {
          "type": "message",
          "text": input
        }

      ]
    }
  }

  console.log("/chat api -- cached chatbot token -- ", token)
  console.log('/chat api - this is the body', reqBody)

  try {
    const response = await axios({
      method: 'POST',
      url: 'https://api.zoom.us/v2/im/chat/messages',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      data: reqBody
    });

    console.log("token:", token)
    console.log("response for zoom api call", response.data)
    res.status(200).send(response.data);
  } catch (error) {
    console.log('Error sending chat.', error)
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
  console.log("/new_vote api -- message sent from zoom", req)
  console.log("/new_vote api -- auth header", req.headers.authorization)
  if (req.headers.authorization === process.env.zoom_verification_token) {
    try {
      const chatbotToken = await getChatbotToken();
      const photo = await getPhoto(req.body.payload.cmd);
      const chatBody = generateChatBody(photo, req.body.payload);
      await sendChat(chatBody, chatbotToken);
      console.log("/new_vote api -- chatbot token -- ", chatbotToken)
      res.status(200).send();
    } catch (error) {
      console.log('Error occurred:', error);
      res.status(500).send('/new_vote api -- Internal Server Error');
    }
  } else {
    console.log("/new_vote api -- random testing")
    res.status(401).send('/new_vote api -- Unauthorized request to Unsplash Chatbot for Zoom.')
  }

  async function getPhoto(query) {
    const response = await axios.get(`https://api.unsplash.com/photos/random?query=${query}&orientation=landscape&client_id=${process.env.unsplash_access_key}`);
    if (response.status !== 200 || response.data.errors) {
      throw new Error('Error getting photo from Unsplash');
    }
    return response.data;
  }

  function generateChatBody(photo, payload) {
    const chatBody = {
      'robot_jid': process.env.zoom_bot_jid,
      'to_jid': payload.toJid,
      "user_jid": payload.userJid,
      'account_id': payload.accountId,
      'content': {
        'head': {
          'text': '/unsplash ' + payload.cmd,
          'sub_head': {
            'text': 'Sent by ' + payload.userName
          }
        },
        'body': [
          {
            'type': 'section',
            'sidebar_color': photo.color,
            'sections': [
              {
                'type': 'attachments',
                'img_url': photo.urls.regular,
                'resource_url': photo.user.links.html,
                'information': {
                  'title': {
                    'text': 'Photo by ' + photo.user.name
                  },
                  'description': {
                    'text': 'Click to view on Unsplash'
                  }
                }
              }
            ]
          }
        ]
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
    if (response.status !== 200) {
      throw new Error('Error sending chat');
    }
  }

  async function getChatbotToken() {
    const response = await axios({
      url: 'https://api.zoom.us/oauth/token',
      method: 'POST',
      headers: {
        'Authorization': `Basic ${Buffer.from(`${process.env.zoom_client_id}:${process.env.zoom_client_secret}`).toString('base64')}`
      },
      params: {
        grant_type: 'client_credentials'
      }
    });
    if (response.status !== 200) {
      throw new Error('Error getting chatbot_token from Zoom');
    }
    return response.data.access_token;
  }
});
app.listen(port, () => console.log(`Unsplash Chatbot for Zoom listening on port ${port}!`))