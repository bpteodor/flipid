use actix_web::cookie::CookieJar;
use actix_web::{HttpRequest, HttpResponse};

#[derive(Debug, Clone, Deserialize, Default, Serialize)]
pub struct AuthSessionCookie {
    pub client_id: String,
    pub scopes: String,
    pub redirect_uri: String,
    pub nonce: Option<String>,
    pub state: Option<String>,
    pub subject: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, Serialize)]
pub struct SSOCookie {
    // id?
    pub subject: String,
    pub client_id: String,
    pub auth_time: i64,
    //pub scopes: String,
}

/**
* fills the cookie jar with the cookies from the request, so the cookie jar can be used to decrypt the cookies
* @param req the request
* @return the filled cookie jar
*/
pub fn fill_cookie_jar(req: HttpRequest) -> CookieJar {
    let mut jar = CookieJar::new();

    // Move cookies from the HttpRequest into the CookieJar
    if let Ok(cookies) = req.cookies() {
        for c in cookies.iter() {
            warn!("got_cookie: {:?}", c);
            // Use add_original so the jar doesn't think these are "new" changes
            jar.add_original(c.clone());
        }
    }

    jar
}

pub fn set_cookies_from_jar(jar: &CookieJar, response: &mut HttpResponse) {
    // iterate the delta (the new/changed/removed cookies) and add to response headers
    for cookie in jar.delta() {
        warn!("set_cookie: {:?}", cookie);
        response.add_cookie(cookie).unwrap();
    }
}
