use super::super::db::schema::{oauth_sessions, oauth_tokens, oauth_clients, oauth_scopes, users};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Queryable, Insertable, Debug, Clone)]
#[table_name = "oauth_clients"]
pub struct OauthClient {
    /// the `client_id` as described in the spec
    pub id: String,
    /// the `client_secret` as described in the spec
    pub secret: String,
    /// the name of the application, to be displayed to the user
    pub name: String,
    /// the `redirect_uri` as described in the spec
    pub callback_url: String,
    // TODO: add support for multiple URLs
    // the (space separated) scopes allowed for the client to request
    pub allowed_scopes: String,
}

impl OauthClient {
    pub fn callback_urls(&self) -> Result<Vec<String>, serde_json::Error> {
        serde_json::from_str::<Vec<String>>(&self.callback_url)
    }
}

#[derive(Serialize, Queryable, Insertable)]
#[table_name = "oauth_scopes"]
pub struct OauthScope {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Insertable, Queryable)]
#[table_name = "oauth_sessions"]
pub struct OauthSession {
    /// random generated id of the session
    pub auth_code: String,
    pub client_id: String,
    pub scopes: String,
    pub nonce: Option<String>,
    pub subject: String, // username
    pub expiration: NaiveDateTime,
    pub auth_time: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Insertable, Queryable)]
#[table_name = "oauth_tokens"]
pub struct OauthToken {
    pub token: String,
    pub token_type: String,
    pub client_id: String,
    pub scopes: Option<String>,
    pub subject: Option<String>, // always set by OIDC?
    pub expiration: Option<i64>,
    pub created: NaiveDateTime,
}

#[derive(Queryable, Insertable, Debug)]
#[table_name = "users"]
pub struct User {
    pub id: String,
    pub password: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    // profile
    pub given_name: String,
    pub family_name: String,
    pub preferred_display_name: Option<String>, // if not provided should use "given_name family_name"
    pub address : Option<String>, // free text
    pub birthdate : Option<String>, // format: "YYYY-MM-DD"
    pub locale : Option<String>, // format: "en-US"
}
