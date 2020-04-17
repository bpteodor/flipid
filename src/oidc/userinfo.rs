use crate::core::{send_json, AppState};
use actix_http::ResponseBuilder;
use actix_web::http::header::AUTHORIZATION;
use actix_web::http::StatusCode;
use actix_web::web::Data;
use actix_web::{HttpRequest, HttpResponse, Result};

///GET /userinfo
///
/// https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
pub async fn userinfo_endoint((req, ctx): (HttpRequest, Data<AppState>)) -> Result<HttpResponse> {
    let token = match extract_token(req) {
        Ok(t) => t,
        Err(e) => return Ok(err_resp(StatusCode::UNAUTHORIZED, &e.0, &e.1)),
    };

    let data = ctx.oauth_db.load_token_data(&token)?;
    debug!(
        "loaded by token: (type: {:?}, client: {:?}, scopes: {:?}, sub: {:?}, created: {:?})",
        &data.token_type, &data.client_id, &data.scopes, &data.subject, &data.created
    );

    if "access" != &data.token_type {
        return Ok(err_resp(StatusCode::FORBIDDEN, "invalid_token", "wrong type"));
    }

    let granted_scopes = match data.scopes {
        Some(x) => x.split_whitespace().collect::<String>(), // split by space
        None => return Ok(err_resp(StatusCode::FORBIDDEN, "forbidden", "Missing scope 'openid'")),
    };
    debug!("granted_scopes: {}", granted_scopes);

    if !granted_scopes.contains("openid") {
        return Ok(err_resp(StatusCode::FORBIDDEN, "forbidden", "Missing scope 'openid'"));
    }
    // if user_id is not set - not an OIDC flow (maybe client credentials?)
    if data.subject.is_none() {
        return Ok(err_resp(StatusCode::FORBIDDEN, "not possible", ""));
    }
    let subject = data.subject.unwrap();

    let user = ctx.user_db.fetch_user(&subject)?;

    // TODO deliver if no openid scope?

    let mut user_info = UserInfoClaims::new(&subject);
    if granted_scopes.contains("email") && user.email.is_some() {
        user_info.email = user.email;
        user_info.email_verified = Some(false); // not suppoerted yet
    }
    if granted_scopes.contains("phone") && user.phone.is_some() {
        user_info.phone_number = user.phone;
        user_info.phone_number_verified = Some(false); // not suppoerted yet
    }
    if granted_scopes.contains("profile") {
        user_info.given_name = Some(String::from(&user.given_name));
        user_info.family_name = Some(String::from(&user.family_name));
        user_info.name = Some(
            user.preferred_display_name
                .unwrap_or(format!("{} {}", user.given_name, user.family_name)),
        );
        user_info.locale = user.locale;
        user_info.birthdate = user.birthdate;
    }
    if granted_scopes.contains("address") {
        user_info.address = user.address;
    }

    // TODO userinfo_encrypted_response_alg
    send_json(StatusCode::OK, user_info)
}

fn err_resp(status: StatusCode, error: &str, error_description: &str) -> HttpResponse {
    let www_auth = format!("error=\"{}\",error_description=\"{}\"", error, error_description);
    info!("userInfo error: {}", &www_auth);
    ResponseBuilder::new(status)
        .header("www-authenticate", www_auth)
        .content_type("text/html; charset=utf-8")
        .body(String::from(error))
}

fn extract_token(req: HttpRequest) -> std::result::Result<String, (String, String)> {
    let auth: &str = match req.headers().get(AUTHORIZATION) {
        Some(h) => h.to_str().unwrap_or(""),
        None => return Err(("token_missing".into(), "no header".into())),
    };
    trace!("auth: {:?}", auth); // keep trace level - security
    if auth.is_empty() {
        return Err(("token_missing".into(), "Bearer token expected".into()));
    }
    if !auth.starts_with("Bearer ") {
        return Err(("invalid_token".into(), "Expected type Bearer.".into()));
    }

    let token = String::from(&auth[7..]);
    debug!("token ok");
    Ok(token)
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct UserInfoClaims<'a> {
    sub: &'a str,
    // profile
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phone_number_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    locale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    birthdate: Option<String>,
}

impl<'a> UserInfoClaims<'a> {
    fn new(sub: &str) -> UserInfoClaims {
        UserInfoClaims {
            sub,
            ..Default::default()
        }
    }
}
