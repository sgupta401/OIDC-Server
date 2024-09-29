# Design

This is an OIDC server built on Spring Boot, utilizing the `spring-boot-starter-oauth2-authorization-server` and `spring-boot-starter-security`. It comes equipped with essential OIDC server functionalities such as the `/authorization`, `/token`, and `/userinfo` endpoints right out of the box. Additionally, it includes basic authentication and consent pages. Spring Security manages user authentication. After authentication, user consent is verified. If consent is already provided, users are redirected back to the redirect URL specified in the authorization parameters. If consent is absent, users can give their consent on the consent page.

The OIDC server configures 3 in-memory test users 
  - sgupta1/password
  - sgupta2/password
  - sgupta3/password

The following in-memory test client is also registered for testing purposes
```
        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("intuit-s3-object-browser")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:8080/callback")
                .postLogoutRedirectUri("http://localhost:8080/logout")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(oidcClient);
    }
```
THe RSA key for JWT token signautre is generated at run time during server startup. The RSA public key is exposed via `/oauth2/jwks` endpoint, which is part of OAuth 2.0 and OpenID Connect (OIDC) specifications. 


**`spring-boot-starter-oauth2-authorization-server`** provides all the OAuth 2.0 and OpenID Connect (OIDC) specifications endpoints. However, in this project, the following endpoints are used. 
- **/token endpoint**: Exchanges the access code for ID and access tokens.
- **/authorize endpoint**: Authenticates the user and issues the access code.
- **/jwks endpoint**: Provides details of the RSA public key.
