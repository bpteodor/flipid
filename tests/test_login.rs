mod common;

use actix_web::cookie::{Cookie, CookieJar};
use actix_web::http::{header::SET_COOKIE, StatusCode};
use actix_web::web::Data;
use actix_web::{test, web, App};
use flipid::core::cookies::AuthSessionCookie;
use flipid::core::models::{OauthClient, User};
use flipid::core::{self, AppState, Secrets};
use flipid::idp::login;
use mockall::predicate::*;
use std::collections::HashSet;
use std::sync::Arc;

const CLIENT_ID: &str = "test1";
const REDIRECT_URI: &str = "http://localhost:8080/callback";

fn test_user() -> User {
    User {
        id: "user@example.com".into(),
        password: "hashed".into(),
        email: Some("user@example.com".into()),
        phone: None,
        given_name: "Test".into(),
        family_name: "User".into(),
        preferred_display_name: None,
        address: None,
        birthdate: None,
        locale: None,
    }
}

fn test_client() -> OauthClient {
    OauthClient {
        id: CLIENT_ID.into(),
        secret: "secret".into(),
        name: "Test".into(),
        callback_url: vec![REDIRECT_URI.into()],
        allowed_scopes: "openid profile".into(),
    }
}

/// Build a `Cookie: flip_auth=<encrypted>` header value encrypted with the test key.
fn flip_auth_cookie_header(scopes: &str) -> String {
    let auth_ses = AuthSessionCookie {
        client_id: CLIENT_ID.into(),
        scopes: scopes.into(),
        redirect_uri: REDIRECT_URI.into(),
        nonce: None,
        state: None,
    };
    let json = serde_json::to_string(&auth_ses).unwrap();
    let key = common::test_key();
    let mut jar = CookieJar::new();
    jar.private_mut(&key).add(Cookie::new("flip_auth", json));
    jar.delta()
        .find(|c| c.name() == "flip_auth")
        .map(|c| format!("{}={}", c.name(), c.value()))
        .unwrap()
}

/// Find a Set-Cookie header by cookie name in the response.
fn find_set_cookie(resp: &actix_web::dev::ServiceResponse, name: &str) -> Option<String> {
    resp.headers().get_all(SET_COOKIE).find_map(|v| {
        let s = v.to_str().unwrap();
        if s.starts_with(&format!("{}=", name)) {
            Some(s.to_string())
        } else {
            None
        }
    })
}

fn make_app_state(
    oauth_db: Box<core::MockOauthDatabase>,
    user_db: Box<core::MockUserDatabase>,
) -> AppState {
    AppState::new(
        common::test_key(),
        oauth_db,
        user_db,
        Arc::new(Secrets::load(&common::test_config().secrets).expect("test secrets")),
        common::test_config(),
    )
}

#[actix_rt::test]
async fn test_login_happy_path_all_scopes_granted() {
    let mut oauth_db = Box::new(core::MockOauthDatabase::new());
    let mut user_db = Box::new(core::MockUserDatabase::new());

    user_db.expect_login().times(1).returning(|_, _| Ok(test_user()));
    user_db
        .expect_fetch_granted_scopes()
        .times(1)
        .returning(|_, _| Ok(HashSet::from(["openid".to_string(), "profile".to_string()])));
    oauth_db.expect_fetch_client_config().times(1).returning(|_| Ok(test_client()));
    oauth_db.expect_save_oauth_session().times(1).returning(|_| Ok(()));

    let mut app = test::init_service(
        App::new()
            .app_data(Data::new(make_app_state(oauth_db, user_db)))
            .route("/idp/login", web::post().to(login)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/idp/login")
        .insert_header(("Content-Type", "application/json"))
        .insert_header(("Cookie", flip_auth_cookie_header("openid profile")))
        .set_payload(r#"{"username":"user@example.com","password":"pass"}"#)
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::FOUND);

    // flip_auth must be cleared (Max-Age=0)
    let flip_auth = find_set_cookie(&resp, "flip_auth").expect("expected flip_auth Set-Cookie");
    assert!(flip_auth.contains("Max-Age=0"), "flip_auth should be expired, got: {}", flip_auth);

    // sso cookie must be set
    assert!(find_set_cookie(&resp, "sso").is_some(), "expected sso Set-Cookie to be present");
}

#[actix_rt::test]
async fn test_login_consent_needed() {
    let oauth_db = Box::new(core::MockOauthDatabase::new());
    let mut user_db = Box::new(core::MockUserDatabase::new());

    user_db.expect_login().times(1).returning(|_, _| Ok(test_user()));
    // no scopes granted yet — handler should respond with scopes to grant
    user_db.expect_fetch_granted_scopes().times(1).returning(|_, _| Ok(HashSet::new()));

    let mut app = test::init_service(
        App::new()
            .app_data(Data::new(make_app_state(oauth_db, user_db)))
            .route("/idp/login", web::post().to(login)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/idp/login")
        .insert_header(("Content-Type", "application/json"))
        .insert_header(("Cookie", flip_auth_cookie_header("openid profile")))
        .set_payload(r#"{"username":"user@example.com","password":"pass"}"#)
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // sso must NOT be set when consent is still needed
    assert!(find_set_cookie(&resp, "sso").is_none(), "sso should not be set before consent");

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["op"], "GRANT");
    assert!(!body["scopes"].as_array().unwrap().is_empty());
}

#[actix_rt::test]
async fn test_login_missing_auth_session() {
    let oauth_db = Box::new(core::MockOauthDatabase::new());
    let user_db = Box::new(core::MockUserDatabase::new());

    let mut app = test::init_service(
        App::new()
            .app_data(Data::new(make_app_state(oauth_db, user_db)))
            .route("/idp/login", web::post().to(login)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/idp/login")
        .insert_header(("Content-Type", "application/json"))
        // intentionally no flip_auth cookie
        .set_payload(r#"{"username":"user@example.com","password":"pass"}"#)
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    // InvalidAuthSession → 412 Precondition Failed
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
}

#[actix_rt::test]
async fn test_login_invalid_credentials() {
    let oauth_db = Box::new(core::MockOauthDatabase::new());
    let mut user_db = Box::new(core::MockUserDatabase::new());

    user_db
        .expect_login()
        .times(1)
        .returning(|_, _| Err(core::error::InternalError::NotFound));

    let mut app = test::init_service(
        App::new()
            .app_data(Data::new(make_app_state(oauth_db, user_db)))
            .route("/idp/login", web::post().to(login)),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/idp/login")
        .insert_header(("Content-Type", "application/json"))
        .insert_header(("Cookie", flip_auth_cookie_header("openid profile")))
        .set_payload(r#"{"username":"user@example.com","password":"wrong"}"#)
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert!(resp.status().is_client_error(), "expected 4xx for invalid credentials, got {}", resp.status());
}
