const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { refreshTokens } = require("./refreshTokens");


async function getRecordings() {
  const tokensFilePath = path.join(__dirname, 'tokens.txt');
  const tokensData = fs.readFileSync(tokensFilePath, 'utf8');
  let accessToken = tokensData.split('\n')[0].split(':')[1].trim(); // Extract the access token from the file

  try {
    const response = await makeApiRequest(accessToken);

    if (response.status !== 200 || response.data.errors) {
      throw new Error('Error getting recordings from Zoom');
    }

    return response.data;
  } catch (error) {
    if (isAccessTokenInvalidOrExpired(error)) {
      console.log('Access token is invalid or expired. Refreshing access token...');

      try {
        accessToken = await refreshTokens();
        const retryResponse = await makeApiRequest(accessToken);

        if (retryResponse.status !== 200 || retryResponse.data.errors) {
          throw new Error('Error getting recordings from Zoom after refreshing the access token');
        }

        return retryResponse.data;
      } catch (refreshError) {
        console.log('Error refreshing access token', refreshError);
        throw new Error('Error refreshing access token');
      }
    }

    throw error;
  }
}
exports.getRecordings = getRecordings;

async function makeApiRequest(accessToken) {
  return await axios.get('https://api.zoom.us/v2/users/me/recordings?from=2023-04-11&to=2023-05-10', {
    headers: {
      'Authorization': `Bearer ${accessToken}`
    }
  });
}
function isAccessTokenInvalidOrExpired(error) {
  return error.response &&
    error.response.status === 401 &&
    error.response.data &&
    error.response.data.code === 124;
}
