require('dotenv').config()
function sendCard() {
  (async () => {
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

      console.log('Zoom JS SDK Configuration', configResponse);

      var content = {
        "content": {
          "head": {
            "type": "message",
            "text": "Zoom"
          },
          "body": [
            {
              "type": "message",
              "text": "Welcome to Zoom"
            }
          ]
        }
      };

      var message = JSON.stringify(content);
      //creating hmac object 

      var timenow = Date.now().toString();
      //passing the data to be hashed
      var data = "v0:" + timenow + ":" + message;

      //Creating the hmac in the required format
      var gen_hmac = CryptoJS.HmacSHA256(data, "<client_id>").toString(CryptoJS.enc.Hex);


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

      console.log("request to zoom api", card);


      //call chat api
      try {
        let chatContext = await zoomSdk.getChatContext();
        console.log("chat context = ", chatContext);
        let chatApiResponse = await fetch('/chat', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            //'x-zoom-app-context': chatContext
          },
          body: JSON.stringify({})
        });
        console.log("chat api response", chatApiResponse)
      }catch (e){
          console.log("chatContext or chat api error - ", e)
      }



    } catch (e) {
      prompt("error");
      console.error(e);
    }
  })();
}
