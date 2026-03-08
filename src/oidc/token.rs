use crate::core;
use crate::core::error::AppError::InternalError;
use crate::core::{basic_auth, error::AppError, models::OauthSession, models::OauthToken, AppState};
use actix_web::http::header::AUTHORIZATION;
use actix_web::web::{Data, Form};
use actix_web::{http::StatusCode, HttpRequest, HttpResponse, Result};
use chrono::{offset::Utc, Duration};
use jwt::{encode, Algorithm, Header};
use rand::distr::Alphanumeric;
use rand::RngExt;

#[derive(Deserialize, Debug, Clone)]
pub struct TokenParams {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
}

/// POST /token
///
/// [Specifications](https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint)
pub async fn token_endpoint((data, state, req): (Form<TokenParams>, Data<AppState>, HttpRequest)) -> Result<HttpResponse> {
    debug!("form: [{:?}]", data);
    match data.grant_type.to_lowercase().as_ref() {
        "authorization_code" => {
            let session = state.oauth_db.consume_oauth_session_by_code(&data.code)?;

            core::validate(session.expiration > Utc::now().naive_utc(), "Expired code")?;

            let client = state
                .oauth_db
                .fetch_client_config(&session.client_id)
                .map_err(|_| AppError::bad_req("failed to load the client config"))?;

            if !client.callback_url.contains(&data.redirect_uri) {
                return Err(AppError::bad_req("redirect_uri mismatch"))?;
            }

            let cred = req.headers().get(AUTHORIZATION).unwrap().to_str().unwrap();
            //trace!("cred: {}", cred);
            if cred != basic_auth(&client.id, &client.secret) {
                info!("invalid credentials");
                return Err(AppError::Unauthorized)?;
            }
            debug!("exchange_auth_code({},{}) = ok", data.grant_type, data.code);

            let access_token: String = rand::rng().sample_iter(&Alphanumeric).take(30).map(char::from).collect::<String>();

            let id_token = gen_id_token(&state, session, &access_token)?;
            core::json_ok(id_token)
        }
        // TODO add refresh_token support?
        _ => {
            error!("exchange_auth_code({},{}) = nok", data.grant_type, data.code);
            Ok(HttpResponse::build(StatusCode::BAD_REQUEST).body("'grant_type' not supported"))
        }
    }
}

fn gen_id_token(state: &AppState, session: OauthSession, access_token: &str) -> Result<TokenResponse, AppError> {
    let now = Utc::now().naive_utc();
    let exp = state.config.oauth.token_exp;

    let claims = IdTokenClaims {
        iss: &state.config.oauth.issuer.clone(),
        sub: &session.subject,
        aud: &session.client_id,
        nonce: session.nonce.as_ref(),
        exp: now.checked_add_signed(Duration::seconds(exp)).unwrap_or(now).and_utc().timestamp(),
        iat: now.and_utc().timestamp(),
        auth_time: session.auth_time.map(|d| d.and_utc().timestamp()),
    };
    debug!("claims: {:?}", &claims);

    let (sign_alg, key) = match state.config.oauth.id_token.signature.as_str() {
        // symetric alg
        "HS256" => (
            Algorithm::HS256,
            &jwt::EncodingKey::from_secret(state.config.oauth.id_token.secret.clone().unwrap().as_bytes()),
        ),
        "HS512" => (
            Algorithm::HS512,
            &jwt::EncodingKey::from_secret(state.config.oauth.id_token.secret.clone().unwrap().as_bytes()),
        ),
        "ES256" => (Algorithm::ES256,&state.es_key),
        // asymetric algorithms
        "RS512" => (Algorithm::RS512, &state.rsa_key),
        // RS256 is default
        _ => (Algorithm::RS256, &state.rsa_key),
    };
    let header = Header::new(sign_alg);
    let id_token = encode(&header, &claims, &key).map_err(|e| {
        log::error!("JWT encoding error. (alg: {:?}) (cause: {})", sign_alg, e);
        InternalError
    })?;

    state
        .oauth_db
        .save_oauth_token(&OauthToken {
            token: String::from(access_token),
            token_type: "access".to_string(),
            client_id: session.client_id,
            scopes: Some(session.scopes),
            subject: Some(session.subject), // set on login
            expiration: Some(exp),
            created: Utc::now().naive_utc(),
        })
        .map_err(|e| e.to_user())?;

    Ok(TokenResponse {
        access_token: access_token.into(),
        refresh_token: Option::None,
        token_type: "Bearer".into(),
        expires_in: state.config.oauth.token_exp,
        id_token,
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    access_token: String,
    token_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    expires_in: i64,
    id_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct IdTokenClaims<STR: AsRef<str>> {
    iss: STR,
    sub: STR,
    aud: STR,
    exp: i64,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<STR>,
    //#[serde(skip_serializing_if = "Option::is_none")]
    //acr: Option<STR>,
    //#[serde(skip_serializing_if = "Option::is_none")]
    //amr: Option<String>,
    //#[serde(skip_serializing_if = "Option::is_none")]
    //azp: Option<String>,
}
