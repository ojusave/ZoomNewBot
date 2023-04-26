//require('dotenv').config()

function sendCard() {
  (async () => {
    try{
    var input = document.getElementById("CardSend");
    var value = input.value;
    console.log("The value of the input is: " + value);
    let chatApiResponse = await fetch('/chat', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        "input": value
      })
    });
      await window.close()
    } catch (e) {
      console.log("Error when creating preview card ", e)
    }

  })();


}


function previewCard() {
  (async () => {
    var input = document.getElementById("CardSend");
    var value = input.value;
    console.log("The value of the input is: " + value);
    var card = {
      "type": "interactiveCard",
      "previewCard": JSON.stringify({
        "title": "DEMO",
        "description": "Preview"
      }),
      "message": JSON.stringify(content),
      "signature": gen_hmac,
      "timestamp": timenow
    };
    try {
      const configResponse = await zoomSdk.config({
        size: { width: 480, height: 360 },
        capabilities: [
          /* Add Capabilities Here */
          'appendCardToCompose',
          'getSupportedJsApis',
          'getRunningContext',
          'openUrl',
          'composeCard',
          'getChatContext',
          'getAppContext'
        ],
      });
      var content = {
        "content": {
          "head": {
            "type": "message",
            "text": value+ "this is header"
          },
          "body": [
            {
              "type": "message",
              "text": value+ "this is body"
            }
          ]
        }
      };

      var message = JSON.stringify(content);
      //creating hmac object 
      
      var timenow = Date.now().toString();
      //passing the data to be hashed
      var data = "v0:" + timenow + ":" + message;
      console.log("cookies", document.cookie)
      var zoomClientSecret = getCookie("zoom_client_secret")
      console.log("client secret", zoomClientSecret)
      //Creating the hmac in the required format
      var gen_hmac = CryptoJS.HmacSHA256(data, zoomClientSecret).toString(CryptoJS.enc.Hex);
      var card = {
        "type": "interactiveCard",
        "previewCard": JSON.stringify({
          "title": value,
          "description": value
        }),
        "message": JSON.stringify(content),
        "signature": gen_hmac,
        "timestamp": timenow
      };
      await zoomSdk.composeCard(card);
      await window.close()
    } catch (e) {
      console.log("Error when creating preview card ", e)
    }

  })();

}

function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
}