# Design

This is spring boot based OIDC server built using `spring-boot-starter-oauth2-authorization-server` and `spring-boot-starter-security`. Boilerplate functionalities related to OIDC server like /authorization, /token, /userinfo endpoints are provided out of the box. Along with that, it provide the basic authentication and consent pages. Spring  security handles the authentication of the user. Once the user is authenticated, the consent is checked and if consent is available, the user is redirected back to the redirect url sent in the authorization parameters. If the consent is not avaialble, the consent is taken from user on the consent page. 

Features used are
1. /token endpoint - To exchange the access code to id and access tokens
2. /authorize endpoint - To authenticate the user and get the access code 
3. /jwks endpoint - To get the RSA public key details
