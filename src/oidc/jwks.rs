use crate::core::error::AppError::InternalError;
use crate::core::{self, AppError, AppState};
use actix_web::http::StatusCode;
use actix_web::web::Data;
use actix_web::{App, HttpRequest, HttpResponse, ResponseError, Result};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use openssl::rsa::Rsa;

/**
 * GET /jwks
 */
pub async fn get_keys((_r, state): (HttpRequest, Data<AppState>)) -> Result<HttpResponse> {

    // collect (kid, exponent, modulus) for all RSA secrets so borrows outlive the Jwk slice
    let rsa_params: Vec<(String, String, String)> = state
        .secrets
        .values()
        .filter(|(_, s)| s.kind == "RSA" /* || s.kind == "RS512"*/)
        .map(|(name, secret)| {
            let rsa = Rsa::private_key_from_pem(&secret.raw).map_err(|_| InternalError)?;
            let exponent = BASE64_URL_SAFE_NO_PAD.encode(rsa.e().to_vec());
            let modulus = BASE64_URL_SAFE_NO_PAD.encode(rsa.n().to_vec());
            Ok((name.clone(), exponent, modulus))
        })
        .collect::<Result<_, actix_web::Error>>()?;

    // TODO: add EC key support (ES256/ES384/ES512)
    let keys: Vec<Jwk> = rsa_params.iter().map(|(kid, e, m)| Jwk::rsa_sig(kid, e, m)).collect();

    core::send_json(StatusCode::OK, Jwks { keys })
}

#[derive(Serialize, Debug, Clone)]
struct Jwks<'a> {
    keys: Vec<Jwk<'a>>,
}

/// [JSON Web Key](https://tools.ietf.org/html/rfc7517)
/// [JSON Web Algorithms](https://tools.ietf.org/html/rfc7518)
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct Jwk<'a> {
    kid: &'a str,
    kty: &'a str,
    #[serde(rename = "use")]
    _use: &'a str,
    //alg: &'a str,

    // RSA (https://tools.ietf.org/html/rfc3447)
    #[serde(skip_serializing_if = "Option::is_none")]
    e: Option<&'a str>, // RSA public exponent
    #[serde(skip_serializing_if = "Option::is_none")]
    n: Option<&'a str>, // RSA modulus n
    //..

    // EC
    #[serde(skip_serializing_if = "Option::is_none")]
    x: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    y: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crv: Option<&'a str>,
    // ...

    // x5c
    // x5t
    // key_ops ?
}

impl<'a> Jwk<'a> {
    fn rsa_sig(kid: &'a str, exponent: &'a str, modulus: &'a str) -> Self {
        Jwk::<'a> {
            kty: "RSA",
            _use: "sig",
            kid,
            e: Some(exponent),
            n: Some(modulus),
            ..Default::default()
        }
    }

    fn ec_sig(kid: &'a str, curveType: &'a str, x_coord: &'a str, y_coord: &'a str) -> Self {
        Jwk::<'a> {
            kty: "EC",
            _use: "sig",
            kid,
            crv: Some(curveType),
            x: Some(x_coord),
            y: Some(y_coord),
            ..Default::default()
        }
    }
}
