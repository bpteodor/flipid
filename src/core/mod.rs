pub mod error;
pub mod models;

use self::error::{AppError, InternalError};
use crate::core::error::AppError::ValidationError;
use actix_web::error::ErrorInternalServerError;
use actix_web::http::header::ContentType;
use actix_web::http::StatusCode;
use actix_web::Error;
use actix_web::{HttpResponse, Result};
use diesel::prelude::*;
#[cfg(test)]
use mockall::{automock, predicate::*};
use std::collections::HashSet;

pub struct AppState {
    // tera template handler
    pub template: Box<tera::Tera>,
    pub oauth_db: Box<dyn OauthDatabase>,
    pub user_db: Box<dyn UserDatabase>,
    pub rsa: Box<jwt::EncodingKey>,
}

impl AppState {
    pub fn new(oauth_db: Box<dyn OauthDatabase>, user_db: Box<dyn UserDatabase>, rsa: jwt::EncodingKey) -> Self {
        AppState {
            template: Box::new(tera::Tera::new("templates/**/*.html").expect("failed to initialize tera templating")),
            oauth_db,
            user_db,
            rsa: Box::new(rsa),
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

pub fn send_json<T: serde::Serialize>(status: StatusCode, obj: T) -> Result<HttpResponse> {
    let content = serde_json::to_string(&obj)?;
    trace!("sending json: [{}] {}", status, content); // can be sensible content

    Ok(HttpResponse::build(status)
        .content_type(ContentType::json())
        .insert_header(("Cache-Control", "no-store"))
        .insert_header(("Pragma", "no-cache"))
        .body(content))
}

pub fn json_ok<T: serde::Serialize>(obj: T) -> Result<HttpResponse> {
    send_json(StatusCode::OK, obj)
}

#[cfg_attr(test, automock)]
pub trait OauthDatabase {
    fn fetch_client_config(&self, client_id: &str) -> QueryResult<models::OauthClient>;
    fn save_oauth_session(&self, session: models::OauthSession) -> Result<(), InternalError>;
    fn consume_oauth_session_by_code(&self, code: &str) -> Result<models::OauthSession, InternalError>;
    fn save_oauth_token(&self, data: &models::OauthToken) -> Result<(), InternalError>;
    fn load_token_data(&self, token: &str) -> Result<models::OauthToken, InternalError>;
}

#[cfg_attr(test, automock)]
pub trait UserDatabase {
    fn login(&self, mail: &str, pass: &str) -> Result<models::User, InternalError>;
    fn fetch_user(&self, mail: &str) -> Result<models::User, InternalError>;
    fn fetch_granted_scopes(&self, cid: &str, uid: &str) -> Result<HashSet<String>, InternalError>;
    fn save_granted_scopes(&self, uid: &str, cid: &str, scopes: &Vec<String>) -> Result<(), InternalError>;
}

pub fn validate(expr: bool, message: &str) -> Result<String, AppError> {
    if !expr {
        info!("{:?}", message);
        return Err(ValidationError {
            msg: message.to_owned(),
        });
    }
    Ok(String::new())
}

pub fn load_file(filename: &str) -> Result<Vec<u8>, Error> {
    use std::io::prelude::*;
    let mut file = std::fs::File::open(filename)?;
    let mut buf: Vec<u8> = Vec::with_capacity(file.metadata()?.len() as usize);
    file.read_to_end(&mut buf)?;
    Ok(buf)
}
