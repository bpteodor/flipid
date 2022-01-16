use crate::config;
//use crate::core;
use crate::core::{AppState};
use actix_web::http::StatusCode;
use actix_web::{HttpResponse, Result};
use actix_web::web::{Data, Query};
use actix_session::Session;

/**
 * GET /oauth/end_session
 *
 * Session Management: https://openid.net/specs/openid-connect-session-1_0-10.html
 * Frontchannel Logout: https://openid.net/specs/openid-connect-frontchannel-1_0.html
 */
pub async fn end_session((_data, _state, _session): (Query<EndSessionParams>, Data<AppState>, Session)) -> Result<HttpResponse> {
    
    let _issuer_url = config::oauth_iss();

    info!("ending session"); // TODO

    Ok(HttpResponse::build(StatusCode::OK)
        .content_type("text/html")
        .header("Cache-Control", "no-store")
        .header("Pragma", "no-cache")
        .body("Session terminated"))
}

pub async fn check_session((_data, _state, _session): (Query<EndSessionParams>, Data<AppState>, Session)) -> Result<HttpResponse> {
    
    info!("checking session"); // TODO

    Ok(HttpResponse::build(StatusCode::OK)
        .content_type("text/html")
        .header("Cache-Control", "no-store")
        .header("Pragma", "no-cache")
        .body("NOT IMPLEMENTED")) // TODO
}
/* ---------------------------------------------------------------------------------------*/

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct EndSessionParams {
    id_token_hint: String,
    client_id: Option<String>, // TODO: required if id_token encrypted
    post_logout_redirect_uri: Option<String>, // where to redirect after
    state: Option<String>,    // opaque value
}

