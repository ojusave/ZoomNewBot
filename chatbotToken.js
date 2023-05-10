const axios = require('axios');
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
  module.exports = {
    getChatbotToken: getChatbotToken
  };
