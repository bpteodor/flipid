use crate::core::config::Config;
use crate::core::{OauthDatabase, UserDatabase};
use actix_web::error::ErrorInternalServerError;
use actix_web::http::StatusCode;
use actix_web::{HttpResponse, Result};

pub struct AppState {
    pub template: tera::Tera,
    pub oauth_db: Box<dyn OauthDatabase>,
    pub user_db: Box<dyn UserDatabase>,
    pub rsa_key: jwt::EncodingKey,
    pub es_key: jwt::EncodingKey,
    pub config: Config,
}

impl AppState {
    pub fn new(oauth_db: Box<dyn OauthDatabase>, user_db: Box<dyn UserDatabase>, rsa: jwt::EncodingKey,es: jwt::EncodingKey, config: Config) -> Self {
        AppState {
            template: tera::Tera::new("templates/**/*.html").expect("failed to initialize tera templating"),
            oauth_db,
            user_db,
            rsa_key: rsa,
            es_key: es,
            config,
        }
    }

    /// creates an HttpResponse based on a template
    pub fn send_page(&self, status: StatusCode, tmpl: &str, model: tera::Context) -> Result<HttpResponse> {
        info!("rendering {}", tmpl);

        let resp = HttpResponse::build(status).content_type("text/html").body(
            self.template
                .render(tmpl, &model)
                .map_err(|_| ErrorInternalServerError("Error rendering template <error.html>"))?,
        );

        Ok(resp)
    }
}

pub fn load_encryption_material(rsa_pem_path: &str) -> jwt::EncodingKey {
    let pem: Vec<u8> = crate::core::load_file(rsa_pem_path).expect("failed to read RSA key file");
    jwt::EncodingKey::from_rsa_pem(&pem).expect("failed to load RSA key")
}

pub fn load_es_key(key_path: &str) -> jwt::EncodingKey {
    let pem: Vec<u8> = crate::core::load_file(key_path).expect("failed to load ES Key");
    jwt::EncodingKey::from_ec_pem(&pem).expect("invalid EC Key") // ecdsa
    //jwt::EncodingKey::from_ed_der(&pem)
    //jwt::EncodingKey::from_ed_pem(&pem).expect("invalid ED Key")
}