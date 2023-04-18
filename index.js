require('dotenv').config()
const express = require('express')
const bodyParser = require('body-parser')
const request = require('request')
const helmet = require('helmet')




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
          scriptSrc: ["'self'", 'https://appssdk.zoom.us/sdk.min.js'],
          imgSrc: ["'self'", `*`],
          'connect-src': 'self',
          'base-uri': 'self',
          'form-action': 'self',
      },
  },
};

app.use(helmet(headers));

app.use(bodyParser.json())

app.get('/', (req, res) => {
  res.send('Welcome to this demo bot')
})

app.get('/authorize', (req, res) => {
  res.redirect('https://zoom.us/launch/chat?jid=robot_'+zoom_bot_jid)
})

app.get('/support', (req, res) => {
  res.send('Post on devforum.zoom.us for support.')
})

app.get('/privacy', (req, res) => {
  res.send('This bot does not store in any information .')
})

app.get('/terms', (req, res) => {
  res.send('Dont use it if you do not want to agree to my terms.')
})

app.get('/documentation', (req, res) => {
  res.send('Try typing "island" to see a photo of an island, or anything else you have in mind!')
})

app.get('/zoomverify/verifyzoom.html', (req, res) => {
  res.send(process.env.zoom_verification_code)
})

app.get('/webview.html', (req, res) => {
  res.setHeader("Content-Security-Policy", "script-src https://appssdk.zoom.us/sdk.js https://0233-2601-641-4000-7840-6c0a-566d-12a5-9b4e.ngrok-free.app/card.js https://0233-2601-641-4000-7840-6c0a-566d-12a5-9b4e.ngrok-free.app/crypto-js.js 'nonce-rAnd0m'")
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


app.post('/new_vote', (req, res) => {
  console.log("message sent from zoom", req)
  console.log("auth header", req.headers.authorization)
  if (req.headers.authorization === process.env.zoom_verification_token) {
    res.status(200)
    res.send()
    getChatbotToken()
  } else {
    console.log("random testing")
    res.status(401)
    res.send('Unauthorized request to Unsplash Chatbot for Zoom.')
  }

  function getPhoto (chatbotToken) {
    request(`https://api.unsplash.com/photos/random?query=${req.body.payload.cmd}&orientation=landscape&client_id=${process.env.unsplash_access_key}`, (error, body) => {
      if (error) {
        console.log('Error getting photo from Unsplash.', error)
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

  function getChatbotToken () {
    request({
      url: `https://api.zoom.us/oauth/token?grant_type=client_credentials`,
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + Buffer.from(process.env.zoom_client_id + ':' + process.env.zoom_client_secret).toString('base64')
      }
    }, (error, httpResponse, body) => {
      if (error) {
        console.log('Error getting chatbot_token from Zoom.', error)
      } else {
        body = JSON.parse(body)
        getPhoto(body.access_token)

    
      }
    })
  }
})

app.post('/deauthorize', (req, res) => {
  if (req.headers.authorization === process.env.zoom_verification_token) {
    res.status(200)
    res.send()
    request({
      url: 'https://api.zoom.us/oauth/data/compliance',
      method: 'POST',
      json: true,
      body: {
        'client_id': req.body.payload.client_id,
        'user_id': req.body.payload.user_id,
        'account_id': req.body.payload.account_id,
        'deauthorization_event_received': req.body.payload,
        'compliance_completed': true
      },
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + Buffer.from(process.env.zoom_client_id + ':' + process.env.zoom_client_secret).toString('base64'),
        'cache-control': 'no-cache'
      }
    }, (error, httpResponse, body) => {
      if (error) {
        console.log(error)
      } else {
        console.log(body)
      }
    })
  } else {
    res.status(401)
    res.send('Unauthorized request to Unsplash Chatbot for Zoom.')
  }
})

app.listen(port, () => console.log(`Unsplash Chatbot for Zoom listening on port ${port}!`))