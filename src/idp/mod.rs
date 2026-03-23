use super::core;
use super::core::error::{AppError, InternalError, InternalError::SessionError};
use super::core::models::OauthSession;
use super::core::AppState;
use crate::core::cookies::{fill_cookie_jar, set_cookies_from_jar, AuthSessionCookie, SSOCookie};
use actix_web::cookie::Cookie;
use actix_web::cookie::{CookieJar, Key};
use actix_web::http::header::CONTENT_LOCATION;
// header "location" is blocked by cors
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json};
use actix_web::{HttpRequest, HttpResponse, Result};
use chrono::DateTime;
use chrono::{offset::Utc, Duration};
use diesel::CombineDsl;
use rand::distr::Alphanumeric;
use rand::RngExt;
use std::collections::{HashMap, HashSet};
use url::Url;
/* ---------------------------------------------------------------------------------------*/

#[derive(Deserialize, Debug)]
pub struct LoginReq {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Debug)]
pub struct GrantScopesResponse {
    pub op: String,
    pub scopes: Vec<String>,
}

pub async fn login((form, state, req): (Json<LoginReq>, Data<AppState>, HttpRequest)) -> Result<HttpResponse> {
    // decode auth-session cookie first to validate the request
    let mut cookie_jar = fill_cookie_jar(req);
    let json_auth_ses = cookie_jar
        .private_mut(&state.cookie_jar_key)
        .get("flip_auth")
        .ok_or_else(|| AppError::bad_auth_session("Auth Session not found or invalid"))?;
    let auth_ses: AuthSessionCookie =
        serde_json::from_str(&json_auth_ses.value()).map_err(|_| AppError::bad_auth_session("failed to parse auth-session"))?;

    cookie_jar.remove(Cookie::build("flip_auth", "").path("/").finish());

    // validate the user
    let user = state.user_db.login(&form.username, &form.password)?;
    info!("user {} authenticated", &form.username);

    let requested_scopes: HashSet<&str> = auth_ses.scopes.split_whitespace().collect();

    let granted_scopes: HashSet<String> = state.user_db.fetch_granted_scopes(&auth_ses.client_id, &user.id)?;
    let mut new_scopes = Vec::new();
    for scope in requested_scopes {
        if !granted_scopes.contains(scope) {
            new_scopes.push(scope.to_owned());
        }
    }

    if new_scopes.is_empty() {
        let sso = SSOCookie {
            client_id: auth_ses.client_id.clone(),
            subject: user.id.clone(),
            auth_time: Utc::now().naive_utc().and_utc().timestamp(),
        };

        let json_sso = serde_json::to_string(&sso)?;
        cookie_jar
            .private_mut(&state.cookie_jar_key)
            .add(Cookie::build("sso", json_sso).path("/").secure(true).http_only(true).finish());

        let callback_url = generate_callback(&state, &auth_ses, &sso)?;
        let mut resp = HttpResponse::Found().append_header((CONTENT_LOCATION, callback_url)).finish();
        set_cookies_from_jar(&cookie_jar, &mut resp);

        Ok(resp)
    } else {
        core::send_json(
            StatusCode::OK,
            GrantScopesResponse {
                op: "GRANT".into(),
                scopes: new_scopes,
            },
        )
    }
}

pub fn generate_callback(state: &AppState, auth_ses: &AuthSessionCookie, sso: &SSOCookie) -> Result<String, InternalError> {
    debug!("generating success callback_uri");

    let client = state
        .oauth_db
        .fetch_client_config(auth_ses.client_id.as_ref())
        .map_err(|_| InternalError::query_fail("failed to load the client config "))?;

    let auth_code: String = rand::rng().sample_iter(&Alphanumeric).take(10).map(char::from).collect::<String>();

    let auth_code_exp = Utc::now()
        .naive_utc()
        .checked_add_signed(Duration::minutes(state.config.oauth.auth_code_exp))
        .unwrap();
    let auth_time = DateTime::from_timestamp(sso.auth_time, 0).unwrap().naive_utc();

    // save the code into db
    state.oauth_db.save_oauth_session(OauthSession {
        auth_code: auth_code.clone(),
        client_id: client.id,
        scopes: auth_ses.scopes.to_string(),
        nonce: auth_ses.nonce.clone(),
        subject: sso.subject.clone(),
        expiration: auth_code_exp,
        auth_time: Some(auth_time),
    })?;

    // add the code to the callback URL and return it
    let mut params: HashMap<&str, &str> = HashMap::new();
    params.insert("code", &auth_code);
    if auth_ses.state.is_some() {
        params.insert("state", auth_ses.state.as_ref().unwrap());
    }
    let callback_url = Url::parse_with_params(&auth_ses.redirect_uri, params).unwrap();
    Ok(callback_url.to_string())
}

pub async fn consent((scopes, state, req): (Json<Vec<String>>, Data<AppState>, HttpRequest)) -> Result<HttpResponse> {
    debug!("consented: [{:?}]", scopes);

    /*let uid: String = session
        .get::<String>("subject")
        .map_err(|e| AppError::bad_req(format!("auth-session: {:?}", e)))?
        .ok_or(AppError::bad_req("invalid auth-session: no <user-id>"))?;
    //.ok_or(AppError::Forbidden("user-id is missing".into()))?;
    let client_id: String = session
        .get::<String>("client_id")?
        .ok_or(AppError::bad_req("invalid auth-session: no <client_id>"))?;

    let mut granted_scopes: HashSet<String> = state.user_db.fetch_granted_scopes(&client_id, &uid)?;
    if !scopes.is_empty() {
        state.user_db.save_granted_scopes(&uid, &client_id, &scopes)?;
        scopes.iter().for_each(|s| {
            granted_scopes.insert(s.clone());
        });
    }
    let granted_scopes_as_str = granted_scopes.into_iter().collect::<Vec<String>>().join(" ");

    let callback_url = generate_callback(&session, &client_id, &state, granted_scopes_as_str)?;*/

    Ok(HttpResponse::Found().append_header((CONTENT_LOCATION, "callback_url")).finish())
}

/**
 * when the user cancels the authentication
 */
pub async fn cancel_login((state): (Data<AppState>)) -> Result<HttpResponse> {
    /*let client_id: String = session
        .get::<String>("client_id")
        .map_err(|_| AppError::bad_req("session error"))?
        .ok_or(AppError::bad_req("client_id is missing"))?;
    let client = state
        .oauth_db
        .fetch_client_config(&client_id)
        .map_err(|_| InternalError::query_fail("failed to load the client config"))?;

    let first_url = client.callback_url.first().ok_or(AppError::InternalError)?;
    let callback_url: String = generate_callback_err(&session, first_url, "access_denied", "User denied access")?;*/
    Ok(HttpResponse::Found().append_header((CONTENT_LOCATION, "callback_url")).finish())
}

fn generate_callback_err(redirect_uri: &str, error: &str, description: &str) -> Result<String, AppError> {
    debug!("generating error callback_uri: [{}] {}", error, description);

    /*let state: Option<String> = session.get("state").unwrap_or(Option::None);

    // add the code to the callback URL and return it
    let mut params: HashMap<&str, &str> = HashMap::new();
    params.insert("error", error);
    params.insert("error_description", description);
    if state.is_some() {
        params.insert("state", state.as_ref().unwrap());
    }
    let callback_url = Url::parse_with_params(redirect_uri, params).unwrap();

    Ok(callback_url.to_string())*/
    Ok("callback_url".into())
}
