# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

FlipID is a lightweight OpenID Provider (OP) implemented in Rust. It aims to be secure, fast, and simple, currently supporting:
- OpenID Connect Discovery
- Authorization Code flow

## Development Commands

### Setup
```bash
# Install system dependencies
apt install libssl-dev libsqlite3-dev

# Install diesel CLI for database migrations
cargo install diesel_cli --no-default-features --features sqlite

# Generate RSA keys for JWT signing (RS256 algorithm)
ssh-keygen -t rsa -b 4096 -C "your_email@example.com" -f ./id_rsa
ssh-keygen -p -m PEM -f id_rsa
openssl rsa -in id_rsa -outform pem > id_rsa.pem

# (Optional) Generate SSL cert + key for the server
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -nodes

# Initialize database
diesel migration run
```

### Build & Run
```bash
# Build debug
cargo build

# Build release
cargo build -r

# Run tests
cargo test
```

### Docker
```bash
# Build container image (debug)
docker build . -t my-flipid

# Build container image (release)
docker build . -t my-flipid --build-arg PROFILE=release

# Run locally with mounted volumes
docker run --rm -ti -p 9000:9000 --name flip-id \
  -v $(pwd)/target/test.db:/app/target/test.db \
  -v $(pwd)/.env:/app/.env:ro \
  -v $(pwd)/config:/app/config:ro \
  -w /app \
  -e "RUN_BEHIND_PROXY=true" \
  my-flipid
```

## Architecture

### Module Structure

The codebase follows a clean separation of concerns:

- **`main.rs`**: Application entry point, sets up actix-web HTTP server with routing, session middleware, CORS, and optional SSL support
- **`config.rs`**: Configuration management via environment variables (`.env` file)
- **`core/`**: Core abstractions and business logic
  - `models.rs`: Data models (OauthClient, OauthSession, OauthToken, User)
  - `error.rs`: Error types (AppError, InternalError)
  - Defines `OauthDatabase` and `UserDatabase` traits for persistence layer abstraction
  - `AppState`: Application state containing Tera templates, database connections, and RSA keys
- **`db/`**: Database layer implementation
  - `schema.rs`: Diesel schema definitions
  - `mod.rs`: `DbSqlBridge` implements `OauthDatabase` and `UserDatabase` traits using SQLite via Diesel ORM
- **`oidc/`**: OpenID Connect protocol endpoints
  - `discovery.rs`: `.well-known/openid-configuration` endpoint
  - `authorize.rs`: Authorization endpoint (OAuth2 authorization code flow)
  - `token.rs`: Token endpoint (exchanges authorization code for tokens)
  - `userinfo.rs`: UserInfo endpoint (returns user claims)
  - `jwks.rs`: JSON Web Key Set endpoint (public keys for token verification)
- **`idp/`**: Identity Provider UI and user authentication
  - Login, consent, and cancellation handlers
  - Session management and scope consent tracking

### Key Design Patterns

1. **Trait-Based Persistence**: `OauthDatabase` and `UserDatabase` traits abstract data access, making the system pluggable for different backends (currently SQLite, but designed for LDAP, Redis, etc.)

2. **Actix-Web Framework**: Uses actix-web for async HTTP handling with:
   - Session middleware with encrypted cookies
   - Request routing to OIDC endpoints
   - Static file serving for UI assets

3. **JWT Token Flow**:
   - RS256 algorithm (RSA signature)
   - Private key loaded from PEM file configured via `OAUTH_JWT_RSA_PEM`
   - Public keys exposed via `/op/jwks` endpoint

4. **Session Flow**:
   - Authorization requests create sessions with scopes, nonce, redirect_uri
   - User authenticates via `/idp/login`
   - User grants consent via `/idp/consent` (tracks granted scopes per user/client)
   - Authorization code issued and stored in `oauth_sessions` table
   - Code exchanged for tokens at `/op/token` (code consumed after use)

5. **Password Security**: User passwords are SHA256 hashed (see [idp/mod.rs:34](src/idp/mod.rs#L34))

### Configuration

All configuration via environment variables (`.env` file):
- `OAUTH_ISSUER`: Base URL for the OpenID Provider (must be set)
- `DATABASE_URL`: SQLite database path (must be set)
- `OAUTH_JWT_RSA_PEM`: Path to RSA private key PEM file (must be set)
- `APP_PORT`: Server port (default: 9000)
- `APP_PROTOCOL`: http or https (default: http)
- `SECURE_COOKIES`: Enable secure cookie flag (default: true)
- `SERVER_CERT`, `SERVER_KEY`: SSL certificate paths (for HTTPS mode)
- `OIDC_AUTH_CODE_EXP`: Authorization code expiration in minutes (default: 60)
- `OAUTH_TOKEN_EXP`: Token expiration in seconds (default: 3600)
- `OAUTH_SCOPES`: Supported scopes (default: "openid profile email phone address")

### Testing

- Unit tests use `mockall` crate for mocking database traits
- Test module: [src/oidc/test_authorize.rs](src/oidc/test_authorize.rs)
- Run with `cargo test`

## Known TODOs

From [TODO.md](TODO.md):
- Finish persistency separation: switchable library for different DBs (LDAP, SQLite, Redis)
- Support more OIDC/auth flows (implicit, client credentials, ROPC)
- Refresh token support
- Introspection endpoint
- SSO + logout
- Dynamic client registration
- More regression tests (at least 1 happy path test per endpoint)

## Important Notes

- Database migrations are managed by Diesel (see `migrations/` directory)
- Templates use Tera templating engine (see `templates/` directory)
- Static resources served from `static/` directory
- The cookie session uses the domain and path from `OAUTH_ISSUER` config
