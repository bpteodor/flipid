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

---

## 5. Authorization Code Flow

### 5.1 Full Flow (Fresh Login with Consent)

The complete login journey for a user with no existing session and scopes that have not yet been granted.

```plantuml
@startuml
title Authorization Code Flow — Full Login with Consent

skinparam defaultFontSize 12
skinparam sequenceArrowThickness 1.5
skinparam roundcorner 6
skinparam sequenceParticipantBorderThickness 1
skinparam noteBorderThickness 1
skinparam noteBackgroundColor #FFFDE7
skinparam noteBorderColor #F9A825

participant "User / Browser" as User #D6EAF8
participant "OAuth2 Client" as Client #D5F5E3
participant "FlipID (OP)" as OP #FDEBD0
database "Database" as DB #EAECEE

Client -> User: redirect to /oauth2/authorize
User -> OP: GET /oauth2/authorize\n(client_id, redirect_uri, scope,\nresponse_type=code, state, nonce)

OP -> OP: validate client_id, redirect_uri,\nresponse_type, scope
OP -> OP: read session cookie\n→ no SSO session found

OP --> User: 200 OK — Login page (HTML)
note right of User
  **Set-Cookie** (HttpOnly, 10 min)
  session: {client_id, scope, nonce,
            redirect_uri, state}
end note

User -> OP: POST /idp/login\n(username, password)\n[Cookie: session={auth params}]
OP -> DB: lookup user by SHA256(password)
DB --> OP: user record
OP -> DB: check granted scopes\nfor subject + client_id
DB --> OP: scopes not all granted
OP --> User: 200 OK — Consent page (HTML)

User -> OP: POST /idp/consent\n(approved scopes)\n[Cookie: session={auth params}]
OP -> DB: save granted scopes\n(subject + client_id)
OP -> DB: generate auth code (10 chars)\nstore with expiry, subject, redirect_uri

OP --> User: 302 Redirect → redirect_uri?code=CODE&state=STATE
note right of User
  **Set-Cookie** (HttpOnly)
  session: {subject, auth_time}
  (replaces auth session — SSO session)
end note

User -> Client: follow redirect\n(delivers code + state)

Client -> OP: POST /oauth2/token\nAuthorization: Basic client_id:secret\ngrant_type=authorization_code\ncode, redirect_uri
OP -> DB: validate code\n(expiry, redirect_uri match, one-time use)
DB --> OP: code record\n(subject, scope, nonce, auth_time)
OP -> OP: generate access_token (30 random chars)
OP -> OP: sign id_token (RS256 JWT)\n{iss, sub, aud, exp, iat, auth_time, nonce}
OP -> DB: store access_token + id_token
OP --> Client: 200 OK — TokenResponse\n{access_token, id_token,\ntoken_type=Bearer, expires_in}

@enduml
```

### 5.2 SSO Flow (Existing Session, All Scopes Already Granted)

When the user already has a valid SSO session cookie and all requested scopes were previously granted, the login and consent steps are skipped entirely.

```plantuml
@startuml
title Authorization Code Flow — SSO (Existing Session)

skinparam defaultFontSize 12
skinparam sequenceArrowThickness 1.5
skinparam roundcorner 6
skinparam sequenceParticipantBorderThickness 1
skinparam noteBorderThickness 1
skinparam noteBackgroundColor #FFFDE7
skinparam noteBorderColor #F9A825

participant "User / Browser" as User #D6EAF8
participant "OAuth2 Client" as Client #D5F5E3
participant "FlipID (OP)" as OP #FDEBD0
database "Database" as DB #EAECEE

Client -> User: redirect to /oauth2/authorize
User -> OP: GET /oauth2/authorize\n(client_id, redirect_uri, scope,\nresponse_type=code, state, nonce)\n[Cookie: session={subject, auth_time}]
note right of User
  **Cookie** (existing SSO session)
  session: {subject, auth_time}
end note

OP -> OP: validate client_id, redirect_uri,\nresponse_type, scope
OP -> OP: decode session cookie\n→ subject, auth_time

OP -> DB: check granted scopes\nfor subject + client_id
DB --> OP: all requested scopes already granted

OP -> DB: generate auth code (10 chars)\nstore with expiry, subject, redirect_uri
OP --> User: 302 Redirect → redirect_uri?code=CODE&state=STATE

User -> Client: follow redirect\n(delivers code + state)

Client -> OP: POST /oauth2/token\nAuthorization: Basic client_id:secret\ngrant_type=authorization_code\ncode, redirect_uri
OP -> DB: validate code\n(expiry, redirect_uri match, one-time use)
DB --> OP: code record\n(subject, scope, nonce, auth_time)
OP -> OP: generate access_token (30 random chars)
OP -> OP: sign id_token (RS256 JWT)\n{iss, sub, aud, exp, iat, auth_time, nonce}
OP -> DB: store access_token + id_token
OP --> Client: 200 OK — TokenResponse\n{access_token, id_token,\ntoken_type=Bearer, expires_in}

@enduml
```

### 5.3 Session Cookie vs. Auth Code

| Artifact | Created at | Stored in | Purpose |
|---|---|---|---|
| Auth session cookie | `GET /oauth2/authorize` | Encrypted HTTP-only cookie (10 min) | Carries `client_id`, `scope`, `nonce`, `redirect_uri`, `state` across the login/consent pages |
| SSO session cookie | After successful login or consent | Encrypted HTTP-only cookie | Carries `subject` + `auth_time` for future SSO reuse |
| Authorization code | After login/consent | Database (one-time use, configurable TTL) | Short-lived token exchanged for final tokens at `/oauth2/token` |
| Access token | `POST /oauth2/token` | Database | Opaque bearer token (30 random chars) |
| ID token | `POST /oauth2/token` | Database | RS256-signed JWT with OIDC claims |
