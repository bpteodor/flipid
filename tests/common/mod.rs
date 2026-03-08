use flipid::core::config::{AuthConfig, Config, CoreConfig, CorsConfig, DatabaseConfig, IdTokenConfig, OauthConfig, ServerConfig};

pub const TEST_RSA_PEM: &str = "tests/resources/config/id_rsa.pem";

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
            //session_key: "123421341234123423432412341234dfsafsfasd".into(),
        },
        oauth: OauthConfig {
            issuer: "https://flipid.local:9000".into(),
            scopes: "openid profile email phone address".into(),
            auth_code_exp: 60,
            token_exp: 3600,
            id_token: IdTokenConfig {
                signature: "RS256".into(),
                rsa_key: TEST_RSA_PEM.into(),
                secret: None,
            },
        },
    }
}
