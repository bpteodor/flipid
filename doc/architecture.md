# Architecture

The project is organized in Rust modules

## 1. CORE

- contains common code
- embedded in the other modules
- should use as few dependencies as possible. Only what can be usefull accross modules (like logging, utilities...)

## 2. DB

- handles communications with an RDBMS
  - currently only sqlite is supported
- it should be used by the other modules, through an abstract layer (interface), that should allow us to swap an RDBMS with LDAP, or file based db

## 3. OIDC

- implements the Oauth2/Opend Id Connect protocol endpoints
- context-path: `/op`
 
| Path              | Name                      | Support |
|-------------------|---------------------------|--|
| /oauth2/authorize     | Authorization Endpoint    | oidc (draft) |
| /oauth2/token         | Token Endpoint            |  |
| /oauth2/userinfo      | UserInfo Endpoint         |  |
| /oauth2/jwks          | JWK Set                   |  |
| /.well-known/openid-configuration | OpenID Connect Discovery |  |

## 4. IDP

- implements IDP specific endpoints, that are not protocol specific
- context-path: `idp`

| Path              | Name                  | Support |
|-------------------|-----------------------|--|
| /idp/login        | Login Page            |  |
| /idp/consent      | Consent Page          |  |
| /idp/cancel       |         |  |

### 4.1 Login-UI

Currently represented as static html pages, it will evolve into an SPA implementing all the required pages (login, consent, registration, etc).
The technology is to be decided (probably VueJS).

