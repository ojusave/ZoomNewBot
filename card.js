const sendCard = async () => {
  const input = document.getElementById("CardSend");
  const value = input.value;
  
  try {
    await fetch('/chat', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ input: value })
    }); 

    window.close();
  } catch (e) {
    console.log("Error when sending messages ", e);
    window.close();
  }
};

const previewCard = async () => {
  const input = document.getElementById("CardSend");
  const value = input.value;
  console.log("The value of the input is: " + value);

  const capabilities = [
    'appendCardToCompose',
    'getSupportedJsApis',
    'getRunningContext',
    'openUrl',
    'composeCard',
    'getChatContext',
    'getAppContext'
  ];

  try {
    const configResponse = await zoomSdk.config({
      size: { width: 480, height: 360 },
      capabilities
    });

    const content = {
      "content": {
        "head": {
          "type": "message",
          "text": `${value} this is header`
        },
        "body": [
          {
            "type": "actions",
            "items": [
              {
                "text": "Add",
                "value": "add",
                "style": "Primary"
              },
              {
                "text": "Update",
                "value": "update",
                "style": "Default"
              }
            ]
          }
        ]
      }
    };

    const message = JSON.stringify(content);

    const timenow = Date.now().toString();
    const data = `v0:${timenow}:${message}`;

    const zoomClientSecret = getCookie("zoom_client_secret");
    const gen_hmac = CryptoJS.HmacSHA256(data, zoomClientSecret).toString(CryptoJS.enc.Hex);

    const card = {
      "type": "interactiveCard",
      "previewCard": JSON.stringify({
        "title": value,
        "description": value
      }),
      "message": JSON.stringify(content),
      "signature": gen_hmac,
      "timestamp": timenow
    };

    console.log(card);

    await zoomSdk.composeCard(card);
   // window.close();
  } catch (e) {
    console.log("Error when creating preview card ", e);
  }
};

const getCookie = (name) => {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
};
