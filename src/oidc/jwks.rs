use crate::core::error::AppError::InternalError;
use crate::core::{self, AppState};
use actix_web::http::StatusCode;
use actix_web::web::Data;
use actix_web::{HttpRequest, HttpResponse, Result};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use openssl::bn::BigNumContext;
use openssl::ec::EcKey;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

/**
 * GET /jwks
 */
pub async fn get_keys((_r, state): (HttpRequest, Data<AppState>)) -> Result<HttpResponse> {
    let mut keys: Vec<Jwk> = Vec::new();

    for (name, secret) in state.secrets.values() {
        match secret.kind.as_str() {
            "RSA" => {
                let rsa = Rsa::private_key_from_pem(&secret.raw).map_err(|_| InternalError)?;
                keys.push(Jwk {
                    kty: "RSA".to_string(),
                    _use: "sig".to_string(),
                    kid: name.clone(),
                    e: Some(BASE64_URL_SAFE_NO_PAD.encode(rsa.e().to_vec())),
                    n: Some(BASE64_URL_SAFE_NO_PAD.encode(rsa.n().to_vec())),
                    ..Default::default()
                });
            }
            "EC" => {
                let ec = EcKey::private_key_from_pem(&secret.raw).map_err(|_| InternalError)?;
                let group = ec.group();
                let mut ctx = BigNumContext::new().map_err(|_| InternalError)?;
                let mut bx = openssl::bn::BigNum::new().map_err(|_| InternalError)?;
                let mut by = openssl::bn::BigNum::new().map_err(|_| InternalError)?;
                ec.public_key()
                    .affine_coordinates_gfp(group, &mut bx, &mut by, &mut ctx)
                    .map_err(|_| InternalError)?;
                let crv = match group.curve_name() {
                    Some(Nid::X9_62_PRIME256V1) => "P-256",
                    Some(Nid::SECP384R1) => "P-384",
                    Some(Nid::SECP521R1) => "P-521",
                    _ => return Err(InternalError.into()),
                };
                keys.push(Jwk {
                    kty: "EC".to_string(),
                    _use: "sig".to_string(),
                    kid: name.clone(),
                    crv: Some(crv.to_string()),
                    x: Some(BASE64_URL_SAFE_NO_PAD.encode(bx.to_vec())),
                    y: Some(BASE64_URL_SAFE_NO_PAD.encode(by.to_vec())),
                    ..Default::default()
                });
            }
            "ED" => {
                let pkey = PKey::private_key_from_pem(&secret.raw).map_err(|_| InternalError)?;
                let pub_bytes = pkey.raw_public_key().map_err(|_| InternalError)?;
                keys.push(Jwk {
                    kty: "OKP".to_string(),
                    _use: "sig".to_string(),
                    kid: name.clone(),
                    crv: Some("Ed25519".to_string()),
                    x: Some(BASE64_URL_SAFE_NO_PAD.encode(&pub_bytes)),
                    ..Default::default()
                });
            }
            _ => {
                // HMAC symmetric keys are not included in JWKS
            }
        }
    }

    core::send_json(StatusCode::OK, Jwks { keys })
}

#[derive(Serialize, Debug, Clone)]
struct Jwks {
    keys: Vec<Jwk>,
}

/// [JSON Web Key](https://tools.ietf.org/html/rfc7517)
/// [JSON Web Algorithms](https://tools.ietf.org/html/rfc7518)
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct Jwk {
    kid: String,
    kty: String,
    #[serde(rename = "use")]
    _use: String,

    // RSA fields (https://tools.ietf.org/html/rfc3447)
    #[serde(skip_serializing_if = "Option::is_none")]
    e: Option<String>, // public exponent
    #[serde(skip_serializing_if = "Option::is_none")]
    n: Option<String>, // modulus

    // EC / OKP fields
    #[serde(skip_serializing_if = "Option::is_none")]
    crv: Option<String>, // curve name
    #[serde(skip_serializing_if = "Option::is_none")]
    x: Option<String>, // EC x-coord or OKP public key
    #[serde(skip_serializing_if = "Option::is_none")]
    y: Option<String>, // EC y-coord
}
