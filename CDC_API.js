/**************************************************************************************                                                                             
                                                                             
                                                                                                                                                       
           _                                                    __    _      
          | |                                                  / _|  | |     
  ___ __ _| |_             ___ ___  _ __  _ __             ___| |_ __| | ___ 
 / __/ _` | __|           / __/ _ \| '_ \| '_ \           / __|  _/ _` |/ __|
| (_| (_| | |_           | (_| (_) | | | | | | |          \__ \ || (_| | (__ 
 \___\__, |\__|           \___\___/|_| |_|_| |_|          |___/_| \__,_|\___|
      __/ |      ______                           ______                     
     |___/      |______|                         |______|                    


                    Created By Balance Spa
                    cgt_conn_sfdc_s
                    versione 1.1
                    18/04/2024
**********************************************************************************************/

async function initiateSSOFlow() {

    document.cookie = "sorgente=sitoCGT";

//-- PCKE Generator --//

    let codeVerifier = generateRandomString();
    localStorage.setItem("pkce_code_verifier", codeVerifier);
        // Hash and base64-urlencode the secret to use as the challenge
    let codeChallenge = await pkceChallengeFromVerifier(codeVerifier);
    let authorizeURI = '/services/oauth2/authorize';
    let responsType = 'code';

//-- Costruzione redirect --//
    let redirectURL = commUrl + authorizeURI +
     '?client_id=' + clientId + 
     '&prompt=login%20consent' +
     '&redirect_uri=' + redirectURI + 
     '&response_type=' + responsType +
     '&sso_provider=' + ssoProvider + 
     '&code_challenge=' + encodeURIComponent(codeChallenge) + 
     '&code_verifier=' + encodeURIComponent(codeVerifier);

//-- Redirect the Browser --//
    window.location = redirectURL;
}

function tokenExchange(response, codeVerifier) {
    // Get Values from Code Response
    let code = response.code;
    let stateIdentifier = response.state;
    let baseURL = response.sfdc_community_url;
    let state = null;
    let tokenURI = '/services/oauth2/token';

// Create Client
    client = new XMLHttpRequest();
    client.open("POST", commUrl + tokenURI, true);
    client.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    //client.setRequestHeader('Access-Control-Allow-Origin', 'https://cridolby.github.io');
    client.setRequestHeader("Access-Control-Allow-Methods", "POST, GET, PUT");
    client.setRequestHeader("Access-Control-Allow-Headers", "Content-Type");
// Build Request Body
    requestBody = "code=" + code + "&grant_type=authorization_code&client_id=" + clientId + "&redirect_uri=" + redirectURI;
// Add PKCE
    requestBody = requestBody + "&code_verifier=" + codeVerifier;
// Send Request
    client.send(requestBody);
    client.onreadystatechange = function() {
        if(this.readyState == 4) {
            if (this.status == 200) {
        //Access Tokens have been returned
                responseArr = JSON.parse(client.response)
                // Creo il cookie
                document.cookie = "SFToken=" +responseArr.access_token +"; path=/; Secure; domain=cgtspa--devmerge.sandbox.my.site.com";
                getUserInfo(responseArr.access_token, commUrl);
            } else {
                    client.onError = function(){
                    error(client, {});
                }
            }
        }
    }
}

function getUserInfo(accessToken) {
    sessionStorage.setItem("sorgente", sorgente);
    userInfoURI = '/services/oauth2/userinfo';
    client = new XMLHttpRequest();
    client.open("GET", commUrl + userInfoURI, true);
    client.setRequestHeader("Content-Type", "application/json");
    client.setRequestHeader("Authorization", 'Bearer ' + accessToken);
    client.send();
    client.onreadystatechange = function() {
        if(this.readyState == 4) {
            if (this.status == 200) {
            //User Info response
            userArr = JSON.parse(client.response)
            localStorage.setItem("user", userArr);
            } else {
                client.onError = function(){
                    error(client, {})
                }
                //onError("An Error Occured during Forgot Password Step: " +
                //forgotPasswordProcessStep, client.response);
            }
        }
    }
}

function logoutUser() {
    let redirectLogoutURL = azureLogoutURI + '?post_logout_redirect_uri=' + redirectURI;
    let revokeTokenURI = '/services/oauth2/revoke';
    let accessToken = getCookie("SFToken");
    client = new XMLHttpRequest();
    client.open("POST", commUrl + revokeTokenURI, true);
    client.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    requestBody = "token=" + accessToken;
    client.send(requestBody);
    client.onreadystatechange = function() {
        if(this.readyState == 4) {
            if (this.status == 200) {
                localStorage.clear();
                sessionStorage.clear()
                document.cookie = "SFToken=; expires=Thu, 01 Jan 1970 00:00:00 UTC;  path=/";
                window.location = redirectLogoutURL;
            } else {
                window.location = redirectLogoutURL;
                //onError("An Error Occured during Forgot Password Step: " +
                //forgotPasswordProcessStep, client.response);
            }
        }
    }
}

    
function parseQueryString(string) {
    if(string == "") { return {}; }
    var segments = string.split("&").map(s => s.split("=") );
    var queryString = {};
    segments.forEach(s => queryString[s[0]] = s[1]);
    return queryString;
}

function generateRandomString() {
    var array = new Uint32Array(28);
    window.crypto.getRandomValues(array);
    return Array.from(array, dec => ('0' + dec.toString(16)).substr(-2)).join('');
}

// Calculate the SHA256 hash of the input text. 
// Returns a promise that resolves to an ArrayBuffer
function sha256(plain) {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);
    return window.crypto.subtle.digest('SHA-256', data);
}

// Base64-urlencodes the input string
function base64urlencode(str) {
    // Convert the ArrayBuffer to string using Uint8 array to conver to what btoa accepts.
    // btoa accepts chars only within ascii 0-255 and base64 encodes them.
    // Then convert the base64 encoded to base64url encoded
    //   (replace + with -, replace / with _, trim trailing =)
    return btoa(String.fromCharCode.apply(null, new Uint8Array(str)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Return the base64-urlencoded sha256 hash for the PKCE challenge
async function pkceChallengeFromVerifier(v) {
    hashed = await sha256(v);
    return base64urlencode(hashed);
}

function getCookie(cname) {
  let name = cname + "=";
  let ca = document.cookie.split(';');
  for(let i = 0; i < ca.length; i++) {
    let c = ca[i];
    while (c.charAt(0) == ' ') {
      c = c.substring(1);
    }
    if (c.indexOf(name) == 0) {
      return c.substring(name.length, c.length);
    }
  }
  return "";
}
