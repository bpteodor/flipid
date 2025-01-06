use actix_web::http::uri::Uri;
use std::str::FromStr;

/// the base URL of the exposed service
pub fn oauth_iss() -> String {
    std::env::var("OAUTH_ISSUER").expect("OAUTH_ISSUER must be set")
}
pub fn base_uri() -> Uri {
    oauth_iss().parse::<Uri>().expect("invalid OAUTH_ISSUER")
}
pub fn port() -> String {
    std::env::var("APP_PORT").unwrap_or("9000".into())
}

pub fn is_protocol_https() -> bool {
    "https" == std::env::var("APP_PROTOCOL").unwrap_or("http".to_string())
}
pub fn is_secure_cookies() -> bool {
    bool::from_str(&std::env::var("SECURE_COOKIES").unwrap_or_default()).unwrap_or(true)
}

pub fn server_cert() -> String {
    dotenv::var("SERVER_CERT").unwrap_or("config/cert.pem".into())
}
pub fn server_key() -> String {
    std::env::var("SERVER_KEY").unwrap_or("config/key.pem".into())
}

pub fn database_url() -> String {
    std::env::var("DATABASE_URL").expect("DATABASE_URL must be set")
}

/// key used for signing / encrypting the session cookie
pub fn session_key() -> Vec<u8> {
    std::env::var("SESSION_KEY")
        .expect("SESSION_KEY must be set")
        .into_bytes()
}

/*pub fn oauth_jwt_secret() -> String {std::env::var("OAUTH_JWT_SECRET").expect("OAUTH_JWT_SECRET must be set")}*/
pub fn oidc_auth_code_exp() -> i64 {
    std::env::var("OIDC_AUTH_CODE_EXP")
        .unwrap_or("60".into())
        .parse::<i64>()
        .unwrap()
}
pub fn oauth_token_exp() -> i64 {
    std::env::var("OAUTH_TOKEN_EXP")
        .unwrap_or("3600".into())
        .parse::<i64>()
        .unwrap()
}
pub fn oauth_rsa_pem() -> String {
    std::env::var("OAUTH_JWT_RSA_PEM").expect("OAUTH_JWT_RSA_PEM must be set")
}
pub fn oauth_supported_scopes() -> String {
    std::env::var("OAUTH_SCOPES").unwrap_or("openid profile email phone address".into())
}
