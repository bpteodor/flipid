use super::OauthError;
use crate::core::{error::AppError, AppState};
use actix_session::Session;
use actix_web::http::header::LOCATION;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Form, Query};
use actix_web::Error;
use actix_web::{HttpResponse, Responder, Result};
use std::collections::HashSet;

/// GET /authorize
pub async fn auth_get((data, state, session): (Query<AuthParams>, Data<AppState>, Session)) -> impl Responder {
    handle_auth(&data, &state, &session)
}

/// POST /authorize
pub async fn auth_post((data, state, session): (Form<AuthParams>, Data<AppState>, Session)) -> impl Responder {
    handle_auth(&data, &state, &session)
}

// common ground
fn handle_auth(data: &AuthParams, state: &Data<AppState>, session: &Session) -> Result<HttpResponse> {
    info!("auth({:?})", data);
    session.clear();
    match validate_auth(data, state)? {
        Some(e) => Ok(HttpResponse::Found()
            .header(LOCATION, callback_error(data, e)?)
            .finish()),
        None => {
            set_on_session(data, session)?;
            state.send_page(StatusCode::OK, "login.html", tera::Context::new())
        }
    }
}

// @see https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
#[derive(Deserialize, Debug, Clone)]
pub struct AuthParams {
    pub scope: Option<String>,
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>, // RECOMMENDED
    pub response_mode: Option<String>,
    pub nonce: Option<String>,
    pub display: Option<String>,
    pub prompt: Option<String>,
    pub max_age: Option<String>,
    pub ui_locales: Option<String>,
    pub id_token_hint: Option<String>,
    pub login_hint: Option<String>,
    pub acr_values: Option<String>,
}

/// validates, extracts the info & puts it on the session
/// https://openid.net/specs/openid-connect-core-1_0.html#AuthError
fn validate_auth(data: &AuthParams, state: &AppState) -> Result<Option<OauthError>, AppError> {
    if data.redirect_uri.is_none() {
        return Err(AppError::bad_req("'redirect_uri' is required"));
    }
    let redirect_uri = data.redirect_uri.as_ref().unwrap();
    if redirect_uri.is_empty() {
        return Err(AppError::bad_req("'redirect_uri' is required"));
    }

    if data.response_type.is_none() {
        return Ok(Some(OauthError::new("invalid_request", "response_type is required.")));
    }
    let response_type = data.response_type.as_ref().unwrap();
    if !contains(&RESPONSE_TYPES, response_type.as_ref()) {
        //if !RESPONSE_TYPES.iter().any(|x| x == &data.response_type) {
        return Ok(Some(OauthError::new("invalid_request", "invalid 'response_type'")));
    }
    if response_type != "code" {
        return Ok(Some(OauthError::of("unsupported_response_type"))); // TODO
    }
    // TODO is responsy_tpe allowed for client?

    if data.client_id.is_none() {
        return Ok(Some(OauthError::new("invalid_request", "'client_id' is required")));
    }
    let client_id = data.client_id.as_ref().unwrap();
    let client = state
        .oauth_db
        .fetch_client_config(&client_id)
        .map_err(|_| AppError::bad_req("Unknown or invalid client_id "))?;

    let callback_urls = client.callback_urls().map_err(|_| AppError::InternalError)?;
    if !callback_urls.contains(&redirect_uri) {
        return Err(AppError::bad_req("'redirect_uri' is invaliid"));
    }

    if data.scope.is_some() {
        let scope_param = data.scope.as_ref().unwrap();
        let scopes: HashSet<&str> = scope_param.split_whitespace().collect();
        if !scopes.contains("openid") {
            // we only support oidc atm
            return Ok(Some(OauthError::new("invalid_request", "scope expected")));
        }

        // only client configured scopes are allowed
        let client_scopes: HashSet<&str> = client.allowed_scopes.split_whitespace().collect();
        if (&scopes - &client_scopes).len() > 0 {
            return Ok(Some(OauthError::new("invalid_scope", "scope not allowed")));
        }
    }

    if data.acr_values.is_some() {
        return Ok(Some(OauthError::new("invalid_request", "invalid acr_value")));
    }

    // TODO! support: "prompt" "display" "ui_locales claims_locales" "auth_time" "max_age" "acr_values"
    // TODO validate

    debug!("no error found");
    Ok(None)
}

fn set_on_session(data: &AuthParams, session: &Session) -> Result<(), Error> {
    session.set("client_id", &data.client_id)?;
    session.set("scopes", &data.scope)?;
    session.set("redirect_uri", &data.redirect_uri)?;
    if data.nonce.is_some() {
        session.set("nonce", data.nonce.as_ref().unwrap())?;
    }
    if data.state.is_some() {
        session.set("state", data.state.as_ref().unwrap())?;
    }
    Ok(())
}

static RESPONSE_TYPES: [&'static str; 8] = [
    "code",
    "token",
    "id_token",
    "id_token token",
    "code id_token",
    "code token",
    "code id_token token",
    "none",
];

pub fn contains<T: PartialEq + AsRef<str>>(col: &[T], item: T) -> bool {
    col.iter().any(|x| &item == x)
}

fn callback_error(data: &AuthParams, err: OauthError) -> Result<String> {
    use std::collections::HashMap;
    use url::Url;
    info!("{:?}", err);

    // add the code to the callback URL and return it
    let mut params: HashMap<&str, &str> = HashMap::new();
    params.insert("error", &err.error);
    if err.error_description.is_some() {
        params.insert("error_description", err.error_description.as_ref().unwrap());
    }
    if data.state.is_some() {
        params.insert("state", data.state.as_ref().unwrap());
    }
    let callback_url = Url::parse_with_params(data.redirect_uri.as_ref().unwrap(), params).unwrap();
    Ok(callback_url.to_string())
}
