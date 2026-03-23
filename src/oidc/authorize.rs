use super::OauthError;
use crate::core::cookies::set_cookies_from_jar;
use crate::core::{
    cookies::{fill_cookie_jar, AuthSessionCookie, SSOCookie},
    error::AppError,
    AppState,
};
use actix_web::cookie::time::Duration;
use actix_web::cookie::{Cookie, CookieJar, Key};
use actix_web::http::header::LOCATION;
use actix_web::http::StatusCode;
use actix_web::web::{Data, Form, Query};
use actix_web::{Error, HttpRequest};
use actix_web::{HttpResponse, Responder, Result};
use std::collections::HashSet;

/// GET /authorize
pub async fn auth_get((data, state, req): (Query<AuthParams>, Data<AppState>, HttpRequest)) -> impl Responder {
    handle_auth(&data, &state, req)
}

/// POST /authorize
pub async fn auth_post((data, state, req): (Form<AuthParams>, Data<AppState>, HttpRequest)) -> impl Responder {
    handle_auth(&data, &state, req)
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

// common ground
fn handle_auth(data: &AuthParams, state: &Data<AppState>, req: HttpRequest) -> Result<HttpResponse> {
    info!("auth({:?})", data);

    match validate_auth(data, state)? {
        Some(e) => {
            info!("Validation ERROR {:?}", &e);
            Ok(HttpResponse::Found().append_header((LOCATION, callback_error(data, e)?)).finish())
        }
        None => {
            if let Some(callback_url) = try_sso(data, state, req)? {
                return Ok(HttpResponse::Found().append_header((LOCATION, callback_url)).finish());
            }

            let mut resp = state.send_page(StatusCode::OK, "login.html", tera::Context::new())?;
            create_auth_session(&state, data, &mut resp)?;
            Ok(resp)
        }
    }
}

fn try_sso(data: &AuthParams, state: &Data<AppState>, req: HttpRequest) -> Result<Option<String>, AppError> {
    let mut cookie_jar = fill_cookie_jar(req);
    let sso_cookie = cookie_jar.private_mut(&state.cookie_jar_key).get("sso");

    let sso = match sso_cookie {
        Some(c) => serde_json::from_str::<SSOCookie>(c.value()).ok(),
        None => None,
    };

    let sso = match sso {
        Some(s) => s,
        None => return Ok(None),
    };

    let client_id = data.client_id.as_ref().unwrap(); // already validated
    let scopes_str = match data.scope.as_ref() {
        Some(s) => s,
        None => return Ok(None),
    };

    let requested_scopes: HashSet<&str> = scopes_str.split_whitespace().collect();
    let granted_scopes: HashSet<String> = state.user_db.fetch_granted_scopes(client_id, &sso.subject).map_err(|e| e.to_user())?;

    let all_granted = requested_scopes.iter().all(|s| granted_scopes.contains(*s));
    if !all_granted {
        return Ok(None);
    }

    let auth_ses = AuthSessionCookie {
        client_id: client_id.clone(),
        scopes: scopes_str.clone(),
        redirect_uri: data.redirect_uri.clone().unwrap(),
        nonce: data.nonce.clone(),
        state: data.state.clone(),
        subject: None,
    };

    let callback_url = crate::idp::generate_callback(state, &auth_ses, &sso).map_err(|e| e.to_user())?;

    info!("SSO: reusing session for subject={}", sso.subject);
    Ok(Some(callback_url))
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
        .fetch_client_config(client_id)
        .map_err(|_| AppError::bad_req("Unknown or invalid client_id "))?;

    if !client.callback_url.contains(redirect_uri) {
        return Err(AppError::bad_req("'redirect_uri' is invalid"));
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
        if !(&scopes - &client_scopes).is_empty() {
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

fn create_auth_session<'a>(state: &'a AppState, data: &'a AuthParams, resp: &mut HttpResponse) -> Result<(), Error> {
    debug!("creating auth-session for {:?}", &data.client_id);

    let auth_ses = AuthSessionCookie {
        client_id: data.client_id.clone().unwrap(),
        scopes: data.scope.clone().unwrap(),
        redirect_uri: data.redirect_uri.clone().unwrap(),
        nonce: data.nonce.clone(),
        state: data.state.clone(),
        subject: None,
    };

    let json_auth_ses = serde_json::to_string(&auth_ses)?;

    let auth_ses_cookie = Cookie::build(state.config.auth.auth_session.clone(), json_auth_ses)
        //.domain("https://openid.local:9000")
        //.domain(_state.config.server.domain.unwrap().as_str())
        .path("/")
        //.secure(true)
        .http_only(true)
        .max_age(Duration::minutes(10))
        .finish();

    let mut jar = CookieJar::new();

    jar.private_mut(&state.cookie_jar_key).add(auth_ses_cookie);

    set_cookies_from_jar(&jar, resp);

    Ok(())
}

static RESPONSE_TYPES: [&str; 8] = [
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
