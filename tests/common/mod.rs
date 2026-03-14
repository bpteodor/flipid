use flipid::core::config::{AuthConfig, Config, CoreConfig, CorsConfig, DatabaseConfig, IdTokenConfig, OauthConfig, SecretConfig, ServerConfig};
use jsonwebtoken::Algorithm;
use std::collections::HashMap;

pub const TEST_RSA_PEM: &str = "tests/resources/config/id_rsa.pem";
pub const TEST_SECRET_NAME: &str = "rsa1";

pub fn test_config() -> Config {
    Config {
        server: ServerConfig {
            address: "127.0.0.1".into(),
            domain: Some("openid.local".into()),
            port: 9000,
            protocol: "http".into(),
            tls: None,
            cors: CorsConfig::default(),
        },
        core: CoreConfig {
            log: None,
            secure_cookies: false,
        },
        database: DatabaseConfig {
            url: "target/test.db".into(),
        },
        auth: AuthConfig {
            session_cookie: "SID".into(),
        },
        oauth: OauthConfig {
            issuer: "https://flipid.local:9000".into(),
            scopes: "openid profile email phone address".into(),
            auth_code_exp: 60,
            token_exp: 3600,
            id_token: IdTokenConfig {
                signing_alg: Algorithm::RS256,
                available_signing: HashMap::from([(Algorithm::RS256, vec![TEST_SECRET_NAME.to_string()])]),
            },
        },
        secrets: vec![SecretConfig {
            name: TEST_SECRET_NAME.into(),
            kind: "RSA".into(),
            value: None,
            file: Some(TEST_RSA_PEM.into()),
        }],
    }
}
