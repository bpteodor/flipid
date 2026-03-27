use crate::core::error::{AppError, AppError::ValidationError};
use actix_web::http::header::ContentType;
use actix_web::http::StatusCode;
use actix_web::{Error, HttpResponse, Result};
use base64::prelude::*;

/// calculates the expected value for the "Authentication" header
///
/// # Examples
/// ```ignore
/// assert_eq!(basic_auth("test", "test"), "Basic dGVzdDp0ZXN0Cg==");
/// ```
pub fn basic_auth(user: &str, pass: &str) -> String {
    let txt = format!("{}:{}", user, pass);
    let b64 = BASE64_STANDARD.encode(txt.as_bytes());
    //trace!("received: {}", b64);
    format!("Basic {}", &b64)
}

pub fn parse_basic_auth(basic_auth_header: &str) -> Option<(String, String)> {
    let encoded = basic_auth_header.strip_prefix("Basic ")?;
    let decoded = BASE64_STANDARD.decode(encoded).ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded_str.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

pub fn send_json<T: serde::Serialize>(status: StatusCode, obj: T) -> Result<HttpResponse> {
    let content = serde_json::to_string(&obj)?;
    trace!("sending json: [{}] {}", status, content); // can be sensible content

    Ok(HttpResponse::build(status)
        .content_type(ContentType::json())
        .insert_header(("Cache-Control", "no-store"))
        .insert_header(("Pragma", "no-cache"))
        .body(content))
}

pub fn json_ok<T: serde::Serialize>(obj: T) -> Result<HttpResponse> {
    send_json(StatusCode::OK, obj)
}

pub fn validate(expr: bool, message: &str) -> Result<String, AppError> {
    if !expr {
        info!("{:?}", message);
        return Err(ValidationError { msg: message.to_owned() });
    }
    Ok(String::new())
}

pub fn load_file(filename: &str) -> Result<Vec<u8>, Error> {
    use std::io::prelude::*;
    let mut file = std::fs::File::open(filename)?;
    let mut buf: Vec<u8> = Vec::with_capacity(file.metadata()?.len() as usize);
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_auth() {
        assert_eq!(basic_auth("admin", "admin"), "Basic YWRtaW46YWRtaW4=");
    }

    #[test]
    fn test_parse_basic_auth() {
        assert_eq!(parse_basic_auth("Basic YWRtaW46YWRtaW4="), Some(("admin".to_owned(), "admin".to_owned())));
    }
}
