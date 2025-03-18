# APISIX OIDC Plugin

## Introduction

This plugin for [apache/apisix](https://github.com/apache/apisix) is used to implement the [token handler pattern](https://curity.io/resources/learn/the-token-handler-pattern/) and pass the access token to the upstream service.

## Endpoints

This plugin responds directly to the following endpoints.

All other endpoints will be proxied upstream when authenticated.

| Name        |                                                                              Description                                                                               |    Method |
|:------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------:|----------:|
| Login       |                                                           Used by the application to trigger the login flow.                                                           |       GET |
| Logout      | Endpoint to Logout from the application and the Identity Provider<br/>- can be called as Fetch/XHR<br/>- can be called as Doc and will redirect to the post logout url | GET, POST |
| Callback    |                                     Callback Endpoint, used to finish the login flow, <br/>will redirec to the Post Login Endpoint                                     |       GET |
| Userinfo    |                                                        Proxy for the userinfo endpoint of the Identity Provider                                                        |       GET |


These endpoints can be configured to get redirected to a specific URL after the action is completed.

| Name        |                                                                              Description                                                                               |    Method |
|:------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------:|----------:|
| Post Login  |                                                             Redirect destination after successfully login.                                                             |       GET |
| Post Logout |                                                                Endpoint to get redirected after Logout                                                                 |       GET |


## Design Decisions

- the plugin will not overwrite the authorization header if it is already set
- the id token is ignored in favor of the userinfo endpoint and the cookie size
- nonce and PKCE are enforced
- access and refresh tokens are stored encrypted (AES-CBC with 32chars key) in the cookie
- a leeway is used to refresh the tokens before they expire to prevent expired tokens in the upstream service
- the signature of the tokens is not verified, this is the responsibility of the upstream service
- the audience of the tokens is not verified, this is the responsibility of the upstream service
- the cookies intended for this plugin are not send to the upstream service


## Configuration

There are no default values, so all fields are required.

```json
{
  "discovery_url": "https://my.idp/.../.well-known/openid-configuration", // URL to the OIDC discovery document
  "client_id": "client-id", 
  "client_secret": "client-secret", 
  "base_url": "http://localhost:9080", // Base URL, used for redirects
  "scope": "openid", 
  "login_path": "/login", 
  "post_login_url": "/post-login", 
  "logout_path": "/logout",
  "post_logout_url": "/post-logout",
  "callback_path": "/callback",
  "userinfo_path": "/userinfo",
  "leeway": 15, // Leeway in seconds to refresh the tokens before they expire
  "cookie": {
    "name": "auth",
    "path": "/",
    "secure": true,
    "http_only": true,
    "same_site": "Lax",
    "secret": "mysecurefixedkey1234567890123456" // needs to be exactly 32 characters long
  }
}
```
