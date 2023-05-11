const axios = require('axios');
const fs = require('fs');
const path = require('path');


async function refreshTokens() {
  const tokensFilePath = path.join(__dirname, 'tokens.txt');
  const tokensData = fs.readFileSync(tokensFilePath, 'utf8');
  const refreshToken = tokensData.split('\n')[1].split(':')[1].trim(); // Extract the refresh token from the file

  try {
    const { zoom_client_id, zoom_client_secret } = process.env;
    const credentials = `${zoom_client_id}:${zoom_client_secret}`;
    const encodedCredentials = Buffer.from(credentials).toString('base64');

    const refreshResponse = await axios.post(
      'https://zoom.us/oauth/token',
      null,
      {
        params: {
          grant_type: 'refresh_token',
          refresh_token: refreshToken
        },
        headers: {
          Authorization: `Basic ${encodedCredentials}`
        }
      }
    );

    const newAccessToken = refreshResponse.data.access_token;
    const newRefreshToken = refreshResponse.data.refresh_token;

    // Update tokens in the text file
    const newTokensData = `access_token: ${newAccessToken}\nrefresh_token: ${newRefreshToken}`;
    fs.writeFileSync(tokensFilePath, newTokensData);

    console.log('New access token:', newAccessToken);

    return newAccessToken;
  } catch (error) {
    console.log('Error refreshing access token', error);
    throw new Error('Error refreshing access token');
  }
}
exports.refreshTokens = refreshTokens;
