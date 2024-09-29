# Design

This is an OIDC server built on Spring Boot, utilizing the `spring-boot-starter-oauth2-authorization-server` and `spring-boot-starter-security`. It comes equipped with essential OIDC server functionalities such as the `/authorization`, `/token`, and `/userinfo` endpoints right out of the box. Additionally, it includes basic authentication and consent pages. Spring Security manages user authentication. After authentication, user consent is verified. If consent is already provided, users are redirected back to the redirect URL specified in the authorization parameters. If consent is absent, users can give their consent on the consent page.

### Key Features used in this project:
- **/token endpoint**: Exchanges the access code for ID and access tokens.
- **/authorize endpoint**: Authenticates the user and issues the access code.
- **/jwks endpoint**: Provides details of the RSA public key.
