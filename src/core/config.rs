use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub core: CoreConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub oauth: OauthConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub address: String,
    pub domain: Option<String>,
    pub port: u16,
    pub protocol: String,
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub cors: CorsConfig,
}

impl ServerConfig {
    pub fn is_https(&self) -> bool {
        self.protocol == "https"
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub cert: String,
    pub key: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CorsConfig {
    #[serde(default)]
    pub allow_origin: Vec<String>,
    #[serde(default)]
    pub allow_methods: Vec<String>,
    #[serde(default)]
    pub allow_headers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CoreConfig {
    pub log: Option<String>,
    #[serde(default = "default_true")]
    pub secure_cookies: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    pub session_cookie: String,
    //pub session_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OauthConfig {
    pub issuer: String,
    pub scopes: String,
    #[serde(default = "default_auth_code_exp")]
    pub auth_code_exp: i64,
    #[serde(default = "default_token_exp")]
    pub token_exp: i64,
    pub id_token: IdTokenConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdTokenConfig {
    pub signature: String,
    pub rsa_key: String,
    pub secret: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_auth_code_exp() -> i64 {
    60
}

fn default_token_exp() -> i64 {
    3600
}

pub fn load(path: impl AsRef<Path>) -> Result<Config, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let config = serde_yaml::from_str(&content)?;
    Ok(config)
}
