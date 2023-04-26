require('dotenv').config()
const express = require('express')
const bodyParser = require('body-parser')
const request = require('request')
const helmet = require('helmet')
const crypto = require('crypto')
const createError = require('http-errors');
const { log } = require('console')
const app = express()
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

const simpleCacheByUid = {};
var appContextCache = {}
var token = ""

app.use(helmet(headers));

app.use(bodyParser.json())

app.get('/', (req, res) => {
  res.send('Welcome to this demo bot')
})

app.get('/authorize', (req, res) => {
  const options = {
    url: 'https://zoom.us/oauth/token',
    method: 'POST',
    headers: {
      'Authorization': 'Basic ' + Buffer.from(process.env.zoom_client_id + ':' + process.env.zoom_client_secret).toString('base64')
    },
    form: {
      grant_type: 'client_credentials'
    }
  };

  request(options, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      const data = JSON.parse(body);
      token = data.access_token;
      res.redirect('https://zoom.us/launch/chat?jid=robot_'+process.env.zoom_bot_jid);
    } else {
      res.status(500).send('Error getting access token');
    }
  });
});


app.get('/zoomverify/verifyzoom.html', (req, res) => {
  res.send(process.env.zoom_verification_code)
})

app.get('/webview.html', (req, res) => {
  var appContext = getAppContext(req.get('x-zoom-app-context'), process.env.zoom_client_secret)
  
  appContextCache = appContext
 
  console.log("/webview api --- app context - ", appContext)
  const {sid}=appContext
  console.log ('/webview api --- SID ', sid)
  req.app.locals.sid = sid
  res.setHeader("Content-Security-Policy", "default-src 'self' * 'nonce-rAnd0m'")
  res.setHeader("X-Frame-Options", "SAMEORIGIN")
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
  res.setHeader("X-Content-Type-Options", "nosniff")
  res.setHeader("Referrer-Policy", "origin")
  res.sendFile(__dirname + '/webview.html');
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

app.post('/chat', (req, res) => {
  console.log("/chat api -- appContextCache --", appContextCache);
  const reqBody = {
    'robot_jid': process.env.zoom_bot_jid,
    'to_jid': appContextCache["sid"], 
    'account_id': process.env.zoom_account_id,
    'user_jid': process.env.zoom_client_id,
    "is_markdown_support": true,
    "content": {
      "settings": {
        "default_sidebar_color": "#357B2A"
      },
      "body": [
        {
          "type": "message",
          "text": "Here are the examples of available commands:"
        }
     
      ]
    }
  }

  console.log("/chat api -- cached chatbot token -- ", token)
  console.log('/chat api - this is the body', reqBody)

     
      request({
        url: 'https://api.zoom.us/v2/im/chat/messages',
        method: 'POST',
        json: true,
        body: {
          'robot_jid': process.env.zoom_bot_jid,
          'to_jid': appContextCache["sid"], 
          'account_id': process.env.zoom_account_id,
          'user_jid': process.env.zoom_client_id,
          "is_markdown_support": true,
          "content": {
            "settings": {
              "default_sidebar_color": "#357B2A"
            },
            "body": [
              {
                "type": "message",
                "text": "Here are the examples of available commands:"
              }
           
            ]
          }
        },
        
        headers: {
          'Content-Type': 'application/json',
          'Authorization': "Bearer " + token //body.access_token
        }
      }, (error, httpResponse, body) => {
        if (error) {
          console.log('Error sending chat.', error)
        } else {
          console.log("token:",token)
          console.log("response for zoom api call", body)
        }
      })
      
  //   }
  // })
})


/**
 * Decodes, parses and decrypts the x-zoom-app-context header
 * @see https://marketplace.zoom.us/docs/beta-docs/zoom-apps/zoomappcontext#decrypting-the-header-value
 * @param {String} header - Encoded Zoom App Context header
 * @param {String} [secret=''] - Client Secret for the Zoom App
 * @return {JSON|Error} Decrypted Zoom App Context or Error
 */
function getAppContext(header, secret = '') {
  console.log('getAppContext -- context header', header)
  if (!header || typeof header !== 'string'){
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

app.post('/new_vote', (req, res) => {
  console.log("/new_vote api -- message sent from zoom", req)
  console.log("/new_vote api -- auth header", req.headers.authorization)
  if (req.headers.authorization === process.env.zoom_verification_token) {
    res.status(200)
    res.send()
    getChatbotToken((error, httpResponse, body) => {
      if (error) {
        console.log('Error getting chatbot_token from Zoom.', error)
      } else {
        body = JSON.parse(body)
        token = body.access_token;
        getPhoto(body.access_token)
        console.log("/new_vote api -- chatbot token -- ", token)
      }
    })
  } else {
    console.log("/new_vote api -- random testing")
    res.status(401)
    res.send('/new_vote api -- Unauthorized request to Unsplash Chatbot for Zoom.')
  }

  function getPhoto (chatbotToken) {
    request(`https://api.unsplash.com/photos/random?query=${req.body.payload.cmd}&orientation=landscape&client_id=${process.env.unsplash_access_key}`, (error, body) => {
      if (error) {
        console.log('/new_vote api -- getPhoto() Error getting photo from Unsplash.', error)
        var errors = [
          {
            'type': 'section',
            'sidebar_color': '#D72638',
            'sections': [{
              'type': 'message',
              'text': 'Error getting photo from Unsplash.'
            }]
          }
        ]
        sendChat(errors, chatbotToken)
      } else {
        body = JSON.parse(body.body)
        if (body.errors) {
          var errors = [
            {
              'type': 'section',
              'sidebar_color': '#D72638',
              'sections': body.errors.map((error) => {
                return { 'type': 'message', 'text': error }
              })
            }
          ]
          sendChat(errors, chatbotToken)
        } else {
          var photo = [
            {
              'type': 'section',
              'sidebar_color': body.color,
              'sections': [
                {
                  'type': 'attachments',
                  'img_url': body.urls.regular,
                  'resource_url': body.user.links.html,
                  'information': {
                    'title': {
                      'text': 'Photo by ' + body.user.name
                    },
                    'description': {
                      'text': 'Click to view on Unsplash'
                    }
                  }
                }
              ]
            }
          ]
          sendChat(photo, chatbotToken)
        }
      }
    })
  }

  function sendChat (chatBody, chatbotToken) {
    request({
      url: 'https://api.zoom.us/v2/im/chat/messages',
      method: 'POST',
      json: true,
      body: {
        'robot_jid': process.env.zoom_bot_jid,
        'to_jid': req.body.payload.toJid,
        "user_jid" : req.body.payload.userJid,
        'account_id': req.body.payload.accountId,

        'content': {
          'head': {
            'text': '/unsplash ' + req.body.payload.cmd,
            'sub_head': {
              'text': 'Sent by ' + req.body.payload.userName
            }
          },
          'body': chatBody
        }
      },
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + chatbotToken
      }
    }, (error, httpResponse, body) => {
      if (error) {
        console.log('Error sending chat.', error)
      } else {
        console.log(body)
      }
    })
  }

})

function getChatbotToken (callback) {
  request({
    url: `https://api.zoom.us/oauth/token?grant_type=client_credentials`,
    method: 'POST',
    headers: {
      'Authorization': 'Basic ' + Buffer.from(process.env.zoom_client_id + ':' + process.env.zoom_client_secret).toString('base64')
    }
  }, (error, httpResponse, body) => {
    callback(error, httpResponse, body)
  })
}

async function getAccessToken () {
  var resp = await request({
    url: `https://api.zoom.us/oauth/token?grant_type=client_credentials`,
    method: 'POST',
    headers: {
      'Authorization': 'Basic ' + Buffer.from(process.env.zoom_client_id + ':' + process.env.zoom_client_secret).toString('base64')
    }
  })
  console.log("getAccessToken() -- accss tokn --", resp)

  return resp.access_token;
}



app.listen(port, () => console.log(`Unsplash Chatbot for Zoom listening on port ${port}!`))