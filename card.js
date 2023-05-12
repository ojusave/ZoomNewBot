document.addEventListener('DOMContentLoaded', () => {
  const fromDate = document.getElementById('fromDate');
  const toDate = document.getElementById('toDate');
  const getRecordingsButton = document.getElementById('getRecordings');
  const meetingIds = document.getElementById('meetingIds');
  const sendPreviewCardButton = document.getElementById('sendPreviewCard');

  // Enable the "Get Recordings" button when both dates are selected
  fromDate.addEventListener('change', updateGetRecordingsButton);
  toDate.addEventListener('change', updateGetRecordingsButton);

  function updateGetRecordingsButton() {
    if (fromDate.value && toDate.value) {
      getRecordingsButton.disabled = false;
    }
  }

  var meetingsData = {}
  // Call the Zoom API when the "Get Recordings" button is clicked
  getRecordingsButton.addEventListener('click', async () => {
    const response = await fetch(`/meetingIds?from=${fromDate.value}&to=${toDate.value}`, { 
      method: 'GET',
      headers: {
        
      },
    });
    meetingsData = await response.json();
    console.log("meetingIds ==>", meetingsData);
    populateMeetingIdsDropdown(meetingsData);
  });
  

  function populateMeetingIdsDropdown(meetings) {
    meetingIds.innerHTML = '';
    for (const id in meetings) {
      const option = document.createElement('option');
      option.text = meetings[id].id;
      option.value =  meetings[id].id;
      meetingIds.appendChild(option);
    }
    meetingIds.disabled = false;
  }

  // Enable the "Send Preview Card" button when a meeting ID is selected
  meetingIds.addEventListener('change', () => {
    if (meetingIds.value) {
      sendPreviewCardButton.disabled = false;
    }
  });

  // Print the selected meeting ID and call your API when the "Send Preview Card" button is clicked
  sendPreviewCardButton.addEventListener('click', async () => {
    const selectedMeetingId = meetingIds.value;
    const meeting = meetingsData[selectedMeetingId];

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
            "text": `Meeting ID: ` + meeting.id
          },
          "body": [
            {
              "type": "actions",
              "items": [
                {
                  "text": "Share Recording URL",
                  "value": "add",
                  "style": "Primary"
                },
                {
                  "text": "Download Recording",
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
          "title": "Meeting ID: "+ meeting.id,
          "description": "Share URL: " + meeting.share_url
        }),
        "message": JSON.stringify(content),
        "signature": gen_hmac,
        "timestamp": timenow
      };
  
      console.log(card);
  
      await zoomSdk.composeCard(card);
      window.close();
    } catch (e) {
      console.log("Error when creating preview card ", e);
    }
  });
});
const getCookie = (name) => {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
};
