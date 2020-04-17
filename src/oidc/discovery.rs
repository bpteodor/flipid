use crate::config;
use crate::core;
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, Result};

/**
 * GET /.well-known/openid-connect
 *
 * Discovery End-Point: https://openid.net/specs/openid-connect-discovery-1_0.html
 */
pub async fn openid_config(_req: HttpRequest) -> Result<HttpResponse> {
    let issuer_url = config::oauth_iss();

    let prov_config = OIDCProviderConfig {
        issuer: issuer_url.clone(),
        authorization_endpoint: issuer_url.clone() + "/op/authorize",
        token_endpoint: issuer_url.clone() + "/op/token",
        userinfo_endpoint: Some(issuer_url.clone() + "/op/userinfo"),
        jwks_uri: issuer_url.clone() + "/op/jwks",
        scopes_supported: Some(supported_scopes()),
        response_types_supported: vec!["code".into()], // TODO support more flows (at least token)
        grant_types_supported: Some(vec!["authorization_code".into()]), // TODO impl. more
        subject_types_supported: vec!["public".into()], // TODO add pairwise too?
        id_token_signing_alg_values_supported: vec![
            "HS256".into(),
            "HS386".into(),
            "HS512".into(),
            "RS256".into(),
            "RS386".into(),
            "RS512".into(),
        ],
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
    id_token_signing_alg_values_supported: Vec<String>, // RS256 must be included
    // ...
    claims_supported: Option<Vec<String>>, // RECOMENDED, default: ["authorization_code", "implicit"]
                                           // ...
                                           // TODO add all fields
}

pub fn supported_scopes() -> Vec<String> {
    let scopes = config::oauth_supported_scopes();
    scopes.split_whitespace().map(String::from).collect::<Vec<String>>()
}

pub static SUPPORTED_ACR_VALUES: [String; 0] = [];
