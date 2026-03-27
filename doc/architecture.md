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

| Path                              | Name                     | Support |
|-----------------------------------|--------------------------|--|
| /oauth2/authorize                 | Authorization Endpoint   | oidc (draft) |
| /oauth2/token                     | Token Endpoint           |  |
| /oauth2/token_info                | Introspection Endpoint   |  |
| /oauth2/user_info                 | UserInfo Endpoint        |  |
| /.well-known/openid-configuration | OpenID Connect Discovery |  |
| /.well-known/jwks.json            | JWK Set                  |  |

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

```mermaid
sequenceDiagram
    participant User as User / Browser
    participant Client as OAuth2 Client
    participant OP as FlipID (OP)
    participant DB as Database

    Client->>User: redirect to /oauth2/authorize
    User->>OP: GET /oauth2/authorize<br/>(client_id, redirect_uri, scope,<br/>response_type=code, state, nonce)

    OP->>OP: validate client_id, redirect_uri,<br/>response_type, scope
    OP->>OP: read session cookie → no SSO session found

    OP-->>User: 200 OK — Login page (HTML)
    Note right of User: Set-Cookie (HttpOnly, 10 min)<br/>session: {client_id, scope, nonce,<br/>redirect_uri, state}

    User->>OP: POST /idp/login<br/>(username, password)<br/>[Cookie: session={auth params}]
    OP->>DB: lookup user by SHA256(password)
    DB-->>OP: user record
    OP->>DB: check granted scopes<br/>for subject + client_id
    DB-->>OP: scopes not all granted
    OP-->>User: 200 OK — Consent page (HTML)

    User->>OP: POST /idp/consent<br/>(approved scopes)<br/>[Cookie: session={auth params}]
    OP->>DB: save granted scopes<br/>(subject + client_id)
    OP->>DB: generate auth code (10 chars)<br/>store with expiry, subject, redirect_uri

    OP-->>User: 302 Redirect → redirect_uri?code=CODE&state=STATE
    Note right of User: Set-Cookie (HttpOnly)<br/>session: {subject, auth_time}<br/>(replaces auth session — SSO session)

    User->>Client: follow redirect<br/>(delivers code + state)

    Client->>OP: POST /oauth2/token<br/>Authorization: Basic client_id:secret<br/>grant_type=authorization_code<br/>code, redirect_uri
    OP->>DB: validate code<br/>(expiry, redirect_uri match, one-time use)
    DB-->>OP: code record<br/>(subject, scope, nonce, auth_time)
    OP->>OP: generate access_token (30 random chars)
    OP->>OP: sign id_token (RS256 JWT)<br/>{iss, sub, aud, exp, iat, auth_time, nonce}
    OP->>DB: store access_token + id_token
    OP-->>Client: 200 OK — TokenResponse<br/>{access_token, id_token,<br/>token_type=Bearer, expires_in}
```

### 5.2 SSO Flow (Existing Session, All Scopes Already Granted)

When the user already has a valid SSO session cookie and all requested scopes were previously granted, the login and consent steps are skipped entirely.

```mermaid
sequenceDiagram
    participant User as User / Browser
    participant Client as OAuth2 Client
    participant OP as FlipID (OP)
    participant DB as Database

    Client->>User: redirect to /oauth2/authorize
    User->>OP: GET /oauth2/authorize<br/>(client_id, redirect_uri, scope,<br/>response_type=code, state, nonce)<br/>[Cookie: session={subject, auth_time}]
    Note right of User: Cookie (existing SSO session)<br/>session: {subject, auth_time}

    OP->>OP: validate client_id, redirect_uri,<br/>response_type, scope
    OP->>OP: decode session cookie → subject, auth_time

    OP->>DB: check granted scopes<br/>for subject + client_id
    DB-->>OP: all requested scopes already granted

    OP->>DB: generate auth code (10 chars)<br/>store with expiry, subject, redirect_uri
    OP-->>User: 302 Redirect → redirect_uri?code=CODE&state=STATE

    User->>Client: follow redirect<br/>(delivers code + state)

    Client->>OP: POST /oauth2/token<br/>Authorization: Basic client_id:secret<br/>grant_type=authorization_code<br/>code, redirect_uri
    OP->>DB: validate code<br/>(expiry, redirect_uri match, one-time use)
    DB-->>OP: code record<br/>(subject, scope, nonce, auth_time)
    OP->>OP: generate access_token (30 random chars)
    OP->>OP: sign id_token (RS256 JWT)<br/>{iss, sub, aud, exp, iat, auth_time, nonce}
    OP->>DB: store access_token + id_token
    OP-->>Client: 200 OK — TokenResponse<br/>{access_token, id_token,<br/>token_type=Bearer, expires_in}
```

### 5.3 Session Cookie vs. Auth Code

| Artifact | Created at | Stored in | Purpose |
|---|---|---|---|
| Auth session cookie | `GET /oauth2/authorize` | Encrypted HTTP-only cookie (10 min) | Carries `client_id`, `scope`, `nonce`, `redirect_uri`, `state` across the login/consent pages |
| SSO session cookie | After successful login or consent | Encrypted HTTP-only cookie | Carries `subject` + `auth_time` for future SSO reuse |
| Authorization code | After login/consent | Database (one-time use, configurable TTL) | Short-lived token exchanged for final tokens at `/oauth2/token` |
| Access token | `POST /oauth2/token` | Database | Opaque bearer token (30 random chars) |
| ID token | `POST /oauth2/token` | Database | RS256-signed JWT with OIDC claims |
