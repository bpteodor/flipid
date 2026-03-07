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

# Run all tests
cargo test

# Run a single test by name
cargo test test_token_happy_path

# Run all tests in a module
cargo test oidc::test_token
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

- **`main.rs`**: Application entry point — sets up actix-web routing, session middleware, CORS, and optional SSL. Also hosts `load_encryption_material()` and `load_server_cert()` helpers used in tests.
- **`config.rs`**: Thin wrappers over `std::env::var` — no caching, read on every call.
- **`core/`**: Shared abstractions. Defines `OauthDatabase` and `UserDatabase` traits (annotated with `#[cfg_attr(test, automock)]` for mockall), `AppState`, and error types.
- **`db/`**: `DbSqlBridge` is the only concrete implementation of both database traits, backed by SQLite via Diesel ORM.
- **`oidc/`**: OIDC protocol endpoints under `/op/`. Each file is one endpoint.
- **`idp/`**: Non-protocol IDP UI handlers under `/idp/` — login, consent, and cancel. Manages the actix session (cookie) between the authorize redirect and the code issuance.

### Key Design Patterns

1. **Trait-Based Persistence**: `OauthDatabase` and `UserDatabase` in `core/mod.rs` abstract all DB access. Tests mock these traits with `mockall`; no real DB is needed for unit tests.

2. **Error Handling**: `InternalError` is used internally by DB/service code. It is converted to `AppError` via `InternalError::to_user()` before returning from handlers. `AppError` implements `ResponseError` for actix-web.

3. **Session Flow**:
   - `GET /op/authorize` stores params (client_id, scopes, nonce, redirect_uri, state) in the encrypted cookie session and renders the login page.
   - `POST /idp/login` authenticates the user, writes `subject`/`auth_time` to session. If all scopes already granted, immediately issues the auth code; otherwise returns scopes needing consent.
   - `POST /idp/consent` saves newly granted scopes and issues the auth code.
   - `POST /op/token` consumes the auth code (one-time use), validates expiry + redirect_uri + Basic auth credentials, issues a JWT id_token (RS256) and a random opaque access_token.

4. **JWT Token Flow**:
   - RS256 — private key path configured via `OAUTH_JWT_RSA_PEM`.
   - `AppState.rsa` holds the loaded `EncodingKey`.
   - Public keys exposed via `GET /op/jwks`.

5. **Password Security**: Passwords are SHA256-hashed before DB lookup ([src/idp/mod.rs:34](src/idp/mod.rs#L34)).

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

- Tests use `mockall`-generated mocks for `OauthDatabase` and `UserDatabase`.
- Test env config: `tests/resources/.env` (points to `tests/resources/config/id_rsa.pem` for the RSA key).
- Test files: [src/oidc/test_authorize.rs](src/oidc/test_authorize.rs), [src/oidc/test_token.rs](src/oidc/test_token.rs).
- `load_encryption_material()` (defined in `main.rs`) is called from tests to build `AppState`.

## Important Notes

- Database migrations are managed by Diesel (see `migrations/` directory).
- Templates use Tera templating engine (see `templates/` directory).
- The cookie session uses the domain and path extracted from `OAUTH_ISSUER`.
- `token_endpoint` panics if the `Authorization` header is missing (line 43 of `token.rs`) — this is a known bug.
