use crate::core;
use crate::core::AppState;
use actix_web::http::StatusCode;
use actix_web::web::Data;
use actix_web::{HttpRequest, HttpResponse, Result};
use jwt::Algorithm;

/**
 * GET /.well-known/openid-connect
 *
 * Discovery End-Point: https://openid.net/specs/openid-connect-discovery-1_0.html
 */
pub async fn openid_config((_req, state): (HttpRequest, Data<AppState>)) -> Result<HttpResponse> {
    let issuer_url = &state.config.oauth.issuer;

    let prov_config = OIDCProviderConfig {
        issuer: issuer_url.clone(),
        authorization_endpoint: issuer_url.clone() + "/oauth2/authorize",
        token_endpoint: issuer_url.clone() + "/oauth2/token",
        userinfo_endpoint: Some(issuer_url.clone() + "/oauth2/userinfo"),
        jwks_uri: issuer_url.clone() + "/oauth2/jwks",
        scopes_supported: Some(supported_scopes(&state.config.oauth.scopes)),
        response_types_supported: vec!["code".into()],                  // TODO token?
        grant_types_supported: Some(vec!["authorization_code".into()]), // TODO impl. more
        subject_types_supported: vec!["public".into()],                 // TODO add pairwise too?
        id_token_signing_alg_values_supported: state.config.oauth.id_token.available_signing.keys().cloned().collect(),
        claims_supported: Some(vec!["sub".into()]),
        acr_values_supported: Some(SUPPORTED_ACR_VALUES.to_vec()),
        ..Default::default()
    };

    core::send_json(StatusCode::OK, prov_config)
}
/* ---------------------------------------------------------------------------------------*/

/**
 * https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
 */
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct OIDCProviderConfig {
    issuer: String,

    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    userinfo_endpoint: Option<String>, // RECOMENDED
    jwks_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    registration_endpoint: Option<String>, // RECOMENDED
    #[serde(skip_serializing_if = "Option::is_none")]
    scopes_supported: Option<Vec<String>>, // RECOMENDED
    response_types_supported: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_modes_supported: Option<Vec<String>>, // OPTIONAL, default: ["query", "fragment"]
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_types_supported: Option<Vec<String>>, // OPTIONAL, default: ["authorization_code", "implicit"]
    #[serde(skip_serializing_if = "Option::is_none")]
    acr_values_supported: Option<Vec<String>>, // OPTIONAL
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<Algorithm>, // RS256 must be included
    // ...
    claims_supported: Option<Vec<String>>, // RECOMENDED, default: ["authorization_code", "implicit"]
                                           // ...
                                           // TODO add all fields
}

pub fn supported_scopes(scopes: &str) -> Vec<String> {
    scopes.split_whitespace().map(String::from).collect::<Vec<String>>()
}

pub static SUPPORTED_ACR_VALUES: [String; 0] = [];
