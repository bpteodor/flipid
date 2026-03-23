use crate::core::config::Config;
use crate::core::secrets::Secrets;
use crate::core::{OauthDatabase, UserDatabase};
use actix_web::cookie::Key;
use actix_web::error::ErrorInternalServerError;
use actix_web::http::StatusCode;
use actix_web::{HttpResponse, Result};
use std::sync::Arc;

pub struct AppState {
    pub template: tera::Tera,
    pub cookie_jar_key: Key,
    pub oauth_db: Box<dyn OauthDatabase>,
    pub user_db: Box<dyn UserDatabase>,
    pub secrets: Arc<Secrets>,
    pub config: Config,
}

impl AppState {
    pub fn new(cookie_jar_key: Key, oauth_db: Box<dyn OauthDatabase>, user_db: Box<dyn UserDatabase>, secrets: Arc<Secrets>, config: Config) -> Self {
        AppState {
            template: tera::Tera::new("templates/**/*.html").expect("failed to initialize tera templating"),
            cookie_jar_key,
            oauth_db,
            user_db,
            secrets,
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
