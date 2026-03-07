use crate::config;
use crate::core::{OauthDatabase, UserDatabase};
use actix_web::error::ErrorInternalServerError;
use actix_web::http::StatusCode;
use actix_web::{HttpResponse, Result};

pub struct AppState {
    pub template: tera::Tera,
    pub oauth_db: Box<dyn OauthDatabase>,
    pub user_db: Box<dyn UserDatabase>,
    pub rsa_key: jwt::EncodingKey,
}

impl AppState {
    pub fn new(oauth_db: Box<dyn OauthDatabase>, user_db: Box<dyn UserDatabase>, rsa: jwt::EncodingKey) -> Self {
        AppState {
            template: tera::Tera::new("templates/**/*.html").expect("failed to initialize tera templating"),
            oauth_db,
            user_db,
            rsa_key: rsa,
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

pub fn load_encryption_material() -> jwt::EncodingKey {
    let pem: Vec<u8> = crate::core::load_file(&config::oauth_rsa_pem()).expect("failed to read certificates");
    jwt::EncodingKey::from_rsa_pem(&pem).expect("failed to load key")
}
