use crate::core::web_util::parse_basic_auth;
use crate::core::{basic_auth, error::AppError, json_ok, AppState};
use actix_web::http::header::AUTHORIZATION;
use actix_web::web::{Data, Form};
use actix_web::{HttpRequest, HttpResponse, Result};
use chrono::{Duration, Utc};

#[derive(Deserialize, Debug)]
pub struct IntrospectParams {
    pub token: String,
    pub token_type_hint: Option<String>,
}

#[derive(Serialize, Default)]
struct IntrospectResponse {
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_type: Option<String>,
}

/// POST /oauth2/token_info
///
/// https://www.rfc-editor.org/rfc/rfc7662
pub async fn introspect((params, state, req): (Form<IntrospectParams>, Data<AppState>, HttpRequest)) -> Result<HttpResponse> {
    debug!("introspect(hint: {:?})", params.token_type_hint);

    if params.token_type_hint != None && params.token_type_hint != Some("access_token".to_owned()) {
        info!("introspect: invalid token_type_hint"); // todo add support for refresh_token
        return json_ok(IntrospectResponse::default());
    }

    match validate_client_credentials(&req, &state) {
        Ok(_) => debug!("introspect: valid credentials"),
        Err(e) => {
            error!("introspect: invalid client credentials: {}", e);
            Err(AppError::Unauthorized)?
        }
    }

    let token_data = match state.oauth_db.load_token_data(&params.token) {
        Ok(t) => t,
        Err(_) => return json_ok(IntrospectResponse::default()),
    };

    let is_active = token_data.expiration.map_or(true, |secs| {
        let exp_time = token_data.created + Duration::seconds(secs);
        exp_time > Utc::now().naive_utc()
    });

    if !is_active {
        debug!("introspect: token expired");
        return json_ok(IntrospectResponse::default());
    }

    let exp = token_data
        .expiration
        .map(|secs| (token_data.created + Duration::seconds(secs)).and_utc().timestamp());

    json_ok(IntrospectResponse {
        active: true,
        scope: token_data.scopes,
        client_id: Some(token_data.client_id),
        sub: token_data.subject,
        exp,
        iat: Some(token_data.created.and_utc().timestamp()),
        token_type: Some(token_data.token_type),
    })
}

fn validate_client_credentials(req: &HttpRequest, state: &Data<AppState>) -> Result<(), String> {
    let raw_basic_auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .ok_or("no authorization header")?
        .to_str()
        .map_err(|_| "header convert error")?;

    let (client_id, _) = parse_basic_auth(&raw_basic_auth_header).ok_or("error parsing basic auth header")?;

    let client = state
        .oauth_db
        .fetch_client_config(&client_id)
        .map_err(|e| format!("error loading client {}: {}", &client_id, e).to_owned())?;

    // todo hash client_secret and verify like user password
    if raw_basic_auth_header != basic_auth(&client.id, &client.secret) {
        Err("invalid credentials")?
    }

    Ok(())
}
