use crate::core::{error::InternalError, models};
use actix_web::Result;
use diesel::prelude::*;
#[cfg(any(test, feature = "testing"))]
use mockall::automock;
use std::collections::HashSet;

#[cfg_attr(any(test, feature = "testing"), automock)]
pub trait OauthDatabase {
    fn fetch_client_config(&self, client_id: &str) -> QueryResult<models::OauthClient>;
    fn save_oauth_session(&self, session: models::OauthSession) -> Result<(), InternalError>;
    fn consume_oauth_session_by_code(&self, code: &str) -> Result<models::OauthSession, InternalError>;
    fn save_oauth_token(&self, data: &models::OauthToken) -> Result<(), InternalError>;
    fn load_token_data(&self, token: &str) -> Result<models::OauthToken, InternalError>;
}

#[cfg_attr(any(test, feature = "testing"), automock)]
pub trait UserDatabase {
    fn login(&self, mail: &str, pass: &str) -> Result<models::User, InternalError>;
    fn fetch_user(&self, mail: &str) -> Result<models::User, InternalError>;
    fn fetch_granted_scopes(&self, cid: &str, uid: &str) -> Result<HashSet<String>, InternalError>;
    fn save_granted_scopes(&self, uid: &str, cid: &str, scopes: &Vec<String>) -> Result<(), InternalError>;
}
