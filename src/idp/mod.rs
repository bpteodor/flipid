use super::core;
use super::core::error::{AppError, InternalError, InternalError::SessionError};
use super::core::models::OauthSession;
use super::core::AppState;
use crate::config;
use actix_session::Session;
use actix_web::http::header::CONTENT_LOCATION; // header "location" is blocked by cors
use actix_web::http::StatusCode;
use actix_web::web::{Data, Json};
use actix_web::{HttpResponse, Result};
use chrono::{naive::NaiveDateTime, offset::Utc, Duration};
use crypto_hash::{hex_digest, Algorithm as Hash};
use rand::distributions::Alphanumeric;
use rand::Rng;
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

pub async fn login((form, state, session): (Json<LoginReq>, Data<AppState>, Session)) -> Result<HttpResponse> {
    let pass_bytes = form.password.to_owned().into_bytes();
    let pass = hex_digest(Hash::SHA256, &pass_bytes);
    let user = state.user_db.login(&form.username, &pass)?;
    info!("user {} authenticated", &form.username);

    let scopes: String = session
        .get::<String>("scopes")?
        .ok_or(AppError::bad_auth_session("no <scope>"))?; //.unwrap_or(String::new());
    let requested_scopes: HashSet<&str> = scopes.split_whitespace().collect();

    let client_id = session
        .get::<String>("client_id")?
        .ok_or(AppError::bad_auth_session("invalid auth-session: no <client_id>"))?;

    let granted_scopes: HashSet<String> = state.user_db.fetch_granted_scopes(&client_id, &user.id)?;
    let mut new_scopes = Vec::new();
    for scope in requested_scopes {
        if !granted_scopes.contains(scope) {
            new_scopes.push(scope.to_owned());
        }
    }
    //let ss = requested_scopes.into_iter().filter(|s| !granted_scopes.contains(s)).collect();

    session.insert("subject", &user.id)?;
    session.insert("auth_time", Utc::now().naive_utc().timestamp())?;

    if new_scopes.len() == 0 {
        let callback_url = generate_callback(&session, &client_id, &state, scopes)?;
        Ok(HttpResponse::Found()
            .append_header((CONTENT_LOCATION, callback_url))
            .finish())
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

fn generate_callback(
    session: &Session,
    client_id: &str,
    state: &AppState,
    scopes: String,
) -> Result<String, InternalError> {
    debug!("generating success callback_uri");

    let client = state
        .oauth_db
        .fetch_client_config(client_id)
        .map_err(|_| InternalError::query_fail("failed to load the client config "))?;

    let auth_code: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect::<String>();

    let auth_code_exp = Utc::now()
        .naive_utc()
        .checked_add_signed(Duration::minutes(config::oidc_auth_code_exp()))
        .unwrap();
    let auth_time = session
        .get::<i64>("auth_time")
        .unwrap()
        .map(|x| NaiveDateTime::from_timestamp(x, 0));

    // save the code into db
    state.oauth_db.save_oauth_session(OauthSession {
        auth_code: auth_code.clone(),
        client_id: client.id,
        scopes: String::from(scopes),
        nonce: session.get::<String>("nonce").unwrap_or(Option::None),
        subject: session.get::<String>("subject").unwrap().unwrap(),
        expiration: auth_code_exp,
        auth_time,
    })?;

    // add the code to the callback URL and return it
    let mut params: HashMap<&str, &str> = HashMap::new();
    params.insert("code", &auth_code);
    let state_param = session.get::<String>("state").map_err(|_| SessionError)?;
    if state_param.is_some() {
        params.insert("state", state_param.as_ref().unwrap());
    }
    let redirect_uri = session.get::<String>("redirect_uri").unwrap().unwrap();
    let callback_url = Url::parse_with_params(&redirect_uri, params).unwrap();
    Ok(callback_url.to_string())
}

pub async fn consent((scopes, state, session): (Json<Vec<String>>, Data<AppState>, Session)) -> Result<HttpResponse> {
    debug!("consented: [{:?}]", scopes);

    let uid: String = session
        .get::<String>("subject")
        .map_err(|e| AppError::bad_req(format!("auth-session: {:?}", e)))?
        .ok_or(AppError::bad_req("invalid auth-session: no <user-id>"))?;
    //.ok_or(AppError::Forbidden("user-id is missing".into()))?;
    let client_id: String = session
        .get::<String>("client_id")?
        .ok_or(AppError::bad_req("invalid auth-session: no <client_id>"))?;

    let mut granted_scopes: HashSet<String> = state.user_db.fetch_granted_scopes(&client_id, &uid)?;
    if scopes.len() > 0 {
        state.user_db.save_granted_scopes(&uid, &client_id, &scopes)?;
        scopes.iter().for_each(|s| {
            granted_scopes.insert(s.clone());
            ()
        });
    }
    let granted_scopes_as_str = granted_scopes.into_iter().collect::<Vec<String>>().join(" ");

    let callback_url = generate_callback(&session, &client_id, &state, granted_scopes_as_str)?;

    Ok(HttpResponse::Found().header(CONTENT_LOCATION, callback_url).finish())
}

/**
 * when the user cancels the authentication
 */
pub async fn cancel_login((state, session): (Data<AppState>, Session)) -> Result<HttpResponse> {
    let client_id: String = session
        .get::<String>("client_id")
        .map_err(|_| AppError::bad_req("session error"))?
        .ok_or(AppError::bad_req("client_id is missing"))?;
    let client = state
        .oauth_db
        .fetch_client_config(&client_id)
        .map_err(|_| InternalError::query_fail("failed to load the client config"))?;

    let callback_url: String =
        generate_callback_err(&session, &client.callback_url, "access_denied", "User denied access")?;
    Ok(HttpResponse::Found()
        .append_header((CONTENT_LOCATION, callback_url))
        .finish())
}

fn generate_callback_err(
    session: &Session,
    redirect_uri: &str,
    error: &str,
    description: &str,
) -> Result<String, AppError> {
    debug!("generating error callback_uri: [{}] {}", error, description);

    let state: Option<String> = session.get("state").unwrap_or(Option::None);

    // add the code to the callback URL and return it
    let mut params: HashMap<&str, &str> = HashMap::new();
    params.insert("error", error);
    params.insert("error_desciption", description);
    if state.is_some() {
        params.insert("state", state.as_ref().unwrap());
    }
    let callback_url = Url::parse_with_params(redirect_uri, params).unwrap();

    Ok(callback_url.to_string())
}
