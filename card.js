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
            'composeCard'
          ],
        });

        console.debug('Zoom JS SDK Configuration', configResponse);

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
        // var hmac = crypto.createHmac('sha256', '2UA0QIuWToWZ8u1Dbe7KRQ');
        var timenow = Date.now().toString();
        //passing the data to be hashed
        var data = "v0:" + timenow + ":" + message;

        //Creating the hmac in the required format
        var gen_hmac = CryptoJS.HmacSHA256(data, "Q8JFJcIxLpQ5zrIALl8MWlEsTvJvbV54").toString(CryptoJS.enc.Hex);


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

        console.log(card);

        let x = await zoomSdk.callZoomApi("composeCard", card);
        console.log("zoom api resp", x);
        // await zoomSdk.composeCard(card);
        await window.close()


      } catch (e) {
        prompt("error");
        console.error(e);
      }
    })();
  }