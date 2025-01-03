use crate::core::error::AppError::InternalError;
use crate::{config, core};
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, Result};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use openssl::rsa::Rsa;

/**
 * GET /jwks
 */
pub async fn get_keys(_r: HttpRequest) -> Result<HttpResponse> {
    let content: Vec<u8> = core::load_file(&config::oauth_rsa_pem()).expect("failed to read certificates");
    let rsa = Rsa::private_key_from_pem(&content).map_err(|_| InternalError)?;

    // TODO add support for multiple key (key rotation)
    let kid = "1";
    let exponent: String = BASE64_URL_SAFE_NO_PAD.encode(&rsa.e().to_vec());
    // base64::encode_config(&rsa.e().to_vec(), base64::URL_SAFE_NO_PAD);
    let modulus: String = BASE64_URL_SAFE_NO_PAD.encode(&rsa.n().to_vec());

    let keys = vec![Jwk::rsa_sig(kid, &exponent, &modulus)];
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
}
