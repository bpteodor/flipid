use crate::core::secrets::verify_password;
use crate::core::web_util::parse_basic_auth;
use crate::core::AppState;
use actix_http::header::AUTHORIZATION;
use actix_web::web::Data;
use actix_web::HttpRequest;

pub fn validate_client_credentials(req: &HttpRequest, state: &Data<AppState>) -> actix_web::Result<(), String> {
    let raw_basic_auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .ok_or("no authorization header")?
        .to_str()
        .map_err(|_| "header convert error")?;

    let (client_id, client_secret) = parse_basic_auth(&raw_basic_auth_header).ok_or("error parsing basic auth header")?;

    let client = state
        .oauth_db
        .fetch_client_config(&client_id)
        .map_err(|e| format!("error loading client {}: {}", &client_id, e).to_owned())?;
    debug!("client {} loaded", &client_id);

    verify_password(&client.secret, &client_secret)?;

    Ok(())
}
