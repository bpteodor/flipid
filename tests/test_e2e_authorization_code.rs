mod common;

use actix_web::http::header::SET_COOKIE;
use actix_web::http::StatusCode;
use actix_web::web::Data;
use actix_web::{test, web, App};
use base64::{engine::general_purpose, Engine as _};
use chrono::Duration;
use flipid::core::models::{OauthClient, OauthSession, OauthToken, User};
use flipid::core::{self, AppState, Secrets};
use flipid::idp::{consent, login};
use flipid::oidc::authorize::auth_get;
use flipid::oidc::token::token_endpoint;
use flipid::oidc::userinfo::userinfo_endpoint;
use std::collections::HashSet;
use std::sync::Arc;
use url::Url;

const CLIENT_ID: &str = "test1";
const CLIENT_SECRET: &str = "test1";
const REDIRECT_URI: &str = "http://localhost:8080/callback";
const USERNAME: &str = "user@example.com";
const NONCE: &str = "test-nonce-123";
/// "test1:test1" base64-encoded
const BASIC_AUTH: &str = "Basic dGVzdDE6dGVzdDE=";

fn test_user() -> User {
    User {
        id: USERNAME.into(),
        password: "hashed".into(),
        email: Some(USERNAME.into()),
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
    let hash = bcrypt::hash(CLIENT_SECRET, 4).unwrap();
    OauthClient {
        id: CLIENT_ID.into(),
        secret: format!("{{BCRYPT}}{}", hash),
        name: "Test App".into(),
        callback_url: vec![REDIRECT_URI.into()],
        allowed_scopes: "openid email profile".into(),
    }
}

fn test_secrets() -> Arc<Secrets> {
    Arc::new(Secrets::load(&common::test_config().secrets).expect("test secrets"))
}

/// Strips cookie attributes from a `Set-Cookie` header, returning only the `name=value` part.
fn cookie_kv(set_cookie: &str) -> &str {
    set_cookie.split(';').next().unwrap_or(set_cookie).trim()
}

/// Finds a `Set-Cookie` by name in the response, ignoring removal entries (Max-Age=0).
fn find_active_cookie(resp: &actix_web::dev::ServiceResponse, name: &str) -> Option<String> {
    resp.headers().get_all(SET_COOKIE).find_map(|v| {
        let s = v.to_str().ok()?;
        if s.starts_with(&format!("{}=", name)) && !s.contains("Max-Age=0") {
            Some(s.to_string())
        } else {
            None
        }
    })
}

/// Extracts the `code` query param from a callback URL.
fn extract_code(callback_url: &str) -> String {
    Url::parse(callback_url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .expect("no 'code' in callback URL")
}

/// Decodes the payload of a JWT without verifying the signature.
fn decode_jwt_payload(token: &str) -> serde_json::Value {
    let payload_b64 = token.split('.').nth(1).expect("JWT must have 3 parts");
    let bytes = general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .expect("invalid base64 in JWT payload");
    serde_json::from_slice(&bytes).expect("JWT payload is not valid JSON")
}

#[actix_rt::test]
async fn test_e2e_authorization_code_flow() {
    let mut oauth_db = Box::new(core::MockOauthDatabase::new());
    let mut user_db = Box::new(core::MockUserDatabase::new());

    // authorize (validate_auth) + consent (generate_callback) + token (validate_credentials + redirect_uri check) = 4 calls
    oauth_db.expect_fetch_client_config().times(4).returning(|_| Ok(test_client()));

    user_db.expect_fetch_user_by_id().times(1).returning(|_| {
        let hash = bcrypt::hash("pass", 4).unwrap();
        Ok(User {
            id: USERNAME.into(),
            password: format!("{{BCRYPT}}{}", hash),
            email: Some(USERNAME.into()),
            phone: None,
            given_name: "Test".into(),
            family_name: "User".into(),
            preferred_display_name: None,
            address: None,
            birthdate: None,
            locale: None,
        })
    });

    // No scopes granted yet — drives through the full consent step
    user_db.expect_fetch_granted_scopes().times(1).returning(|_, _| Ok(HashSet::new()));

    user_db.expect_save_granted_scopes().times(1).returning(|_, _, _| Ok(()));

    oauth_db.expect_save_oauth_session().times(1).returning(|_| Ok(()));

    oauth_db.expect_consume_oauth_session_by_code().times(1).returning(|c| {
        Ok(OauthSession {
            auth_code: c.to_string(),
            client_id: CLIENT_ID.into(),
            scopes: "openid email".into(),
            nonce: Some(NONCE.into()),
            subject: USERNAME.into(),
            expiration: chrono::Utc::now().naive_utc() + Duration::minutes(60),
            auth_time: None,
        })
    });

    oauth_db.expect_save_oauth_token().times(1).returning(|_| Ok(()));

    oauth_db.expect_load_token_data().times(1).returning(|t| {
        Ok(OauthToken {
            token: t.to_string(),
            token_type: "access".into(),
            client_id: CLIENT_ID.into(),
            scopes: Some("openid email".into()),
            subject: Some(USERNAME.into()),
            expiration: Some(chrono::Utc::now().timestamp() + 3600),
            created: chrono::Utc::now().naive_utc(),
        })
    });

    user_db.expect_fetch_user_by_id().times(1).returning(|_| Ok(test_user()));

    let mut app = test::init_service(
        App::new()
            .app_data(Data::new(AppState::new(
                common::test_key(),
                oauth_db,
                user_db,
                test_secrets(),
                common::test_config(),
            )))
            .route("/oauth2/authorize", web::get().to(auth_get))
            .route("/idp/login", web::post().to(login))
            .route("/idp/consent", web::post().to(consent))
            .route("/oauth2/token", web::post().to(token_endpoint))
            .route("/oauth2/userinfo", web::get().to(userinfo_endpoint)),
    )
    .await;

    // ── Step 1: GET /oauth2/authorize ─────────────────────────────────────────
    // Uses percent-encoded redirect_uri to keep the query string unambiguous.
    let resp = test::call_service(
        &mut app,
        test::TestRequest::get()
            .uri(&format!(
                "/oauth2/authorize?client_id={}&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback\
                 &response_type=code&scope=openid+email&nonce={}&state=test-state",
                CLIENT_ID, NONCE
            ))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "authorize should render the login page");

    let flip_auth_1 = find_active_cookie(&resp, "flip_auth").expect("authorize must set flip_auth cookie");
    let flip_auth_1 = cookie_kv(&flip_auth_1).to_string();

    // ── Step 2: POST /idp/login (consent required) ────────────────────────────
    let resp = test::call_service(
        &mut app,
        test::TestRequest::post()
            .uri("/idp/login")
            .insert_header(("Content-Type", "application/json"))
            .insert_header(("Cookie", flip_auth_1))
            .set_payload(format!(r#"{{"username":"{}","password":"pass"}}"#, USERNAME))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "login should return consent request");

    let flip_auth_2 = find_active_cookie(&resp, "flip_auth").expect("login must return updated flip_auth cookie containing the subject");
    let flip_auth_2 = cookie_kv(&flip_auth_2).to_string();

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["op"], "GRANT");
    assert!(!body["scopes"].as_array().unwrap().is_empty(), "scopes to grant must not be empty");

    // ── Step 3: POST /idp/consent ─────────────────────────────────────────────
    let resp = test::call_service(
        &mut app,
        test::TestRequest::post()
            .uri("/idp/consent")
            .insert_header(("Content-Type", "application/json"))
            .insert_header(("Cookie", flip_auth_2))
            .set_payload(r#"["openid","email"]"#)
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FOUND, "consent must redirect to callback");

    let callback_url = resp
        .headers()
        .get("content-location")
        .expect("consent must set content-location header")
        .to_str()
        .unwrap()
        .to_string();
    assert!(callback_url.starts_with(REDIRECT_URI), "callback must point to registered redirect_uri");

    let code = extract_code(&callback_url);
    assert!(!code.is_empty(), "auth code must not be empty");

    // ── Step 4: POST /oauth2/token ────────────────────────────────────────────
    let resp = test::call_service(
        &mut app,
        test::TestRequest::post()
            .uri("/oauth2/token")
            .insert_header(("Authorization", BASIC_AUTH))
            .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
            .set_payload(format!("grant_type=authorization_code&code={}&redirect_uri={}", code, REDIRECT_URI))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "token exchange must succeed");

    let token_resp: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(token_resp["token_type"], "Bearer");
    assert!(token_resp["expires_in"].is_number());

    let access_token = token_resp["access_token"].as_str().expect("access_token must be present").to_string();
    let id_token = token_resp["id_token"].as_str().expect("id_token must be present").to_string();

    // Validate id_token JWT claims (no signature check needed — key is controlled by test config)
    let claims = decode_jwt_payload(&id_token);
    assert_eq!(claims["sub"], USERNAME, "id_token sub must match the authenticated user");
    assert_eq!(claims["aud"], CLIENT_ID, "id_token aud must match the client");
    assert_eq!(
        claims["iss"], "https://flipid.local:9000",
        "id_token iss must match the configured issuer"
    );
    assert_eq!(
        claims["nonce"], NONCE,
        "id_token nonce must echo back the nonce from the authorize request"
    );

    // ── Step 5: GET /oauth2/userinfo ──────────────────────────────────────────
    let resp = test::call_service(
        &mut app,
        test::TestRequest::get()
            .uri("/oauth2/userinfo")
            .insert_header(("Authorization", format!("Bearer {}", access_token)))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "userinfo must succeed with valid access token");

    let userinfo: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(userinfo["sub"], USERNAME);
    assert_eq!(userinfo["email"], USERNAME);
    assert!(
        userinfo.get("given_name").is_none(),
        "profile scope not requested — given_name must be absent"
    );
}
