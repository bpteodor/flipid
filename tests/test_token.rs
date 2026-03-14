mod common;

use actix_web::http::StatusCode;
use actix_web::{test, web, web::Data, App};
use flipid::core::models::{OauthClient, OauthSession};
use flipid::core::{self, AppState, Secrets};
use flipid::oidc::token::token_endpoint;
use mockall::predicate::*;
use std::sync::Arc;

fn test_client() -> OauthClient {
    OauthClient {
        id: "test1".into(),
        secret: "test1".into(),
        name: "Test1".into(),
        callback_url: vec!["http://localhost:8080/callback".into()],
        allowed_scopes: "openid profile email phone address".into(),
    }
}

fn future_session(code: &str) -> OauthSession {
    OauthSession {
        auth_code: code.into(),
        client_id: "test1".into(),
        scopes: "openid profile".into(),
        nonce: None,
        subject: "user@example.com".into(),
        expiration: chrono::Utc::now().naive_utc() + chrono::Duration::minutes(60),
        auth_time: None,
    }
}

fn expired_session(code: &str) -> OauthSession {
    OauthSession {
        auth_code: code.into(),
        client_id: "test1".into(),
        scopes: "openid profile".into(),
        nonce: None,
        subject: "user@example.com".into(),
        expiration: chrono::Utc::now().naive_utc() - chrono::Duration::minutes(1),
        auth_time: None,
    }
}

fn test_secrets() -> Arc<Secrets> {
    let cfg = common::test_config();
    Arc::new(Secrets::load(&cfg.secrets).expect("failed to load test secrets"))
}

fn mock_app_state() -> AppState {
    let oauth_db = Box::new(core::MockOauthDatabase::new());
    let user_db = Box::new(core::MockUserDatabase::new());
    AppState::new(oauth_db, user_db, test_secrets(), common::test_config())
}

/// "test1:test1" base64-encoded
const VALID_AUTH: &str = "Basic dGVzdDE6dGVzdDE=";
const CODE: &str = "test-auth-code-123";
const REDIRECT: &str = "http://localhost:8080/callback";

#[actix_rt::test]
async fn test_token_happy_path() {
    let mut oauth_db = Box::new(core::MockOauthDatabase::new());
    let user_db = Box::new(core::MockUserDatabase::new());

    oauth_db
        .expect_consume_oauth_session_by_code()
        .with(eq(CODE))
        .times(1)
        .returning(|c| Ok(future_session(c)));

    oauth_db
        .expect_fetch_client_config()
        .with(eq("test1"))
        .times(1)
        .returning(|_| Ok(test_client()));

    oauth_db.expect_save_oauth_token().times(1).returning(|_| Ok(()));

    let mut app = test::init_service(
        App::new()
            .app_data(Data::new(AppState::new(oauth_db, user_db, test_secrets(), common::test_config())))
            .route("/oauth2/token", web::post().to(token_endpoint)),
    )
    .await;

    let body = format!("grant_type=authorization_code&code={}&redirect_uri={}", CODE, REDIRECT);
    let req = test::TestRequest::post()
        .uri("/oauth2/token")
        .insert_header(("Authorization", VALID_AUTH))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(body)
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["access_token"].is_string());
    assert!(body["id_token"].is_string());
    assert!(body["expires_in"].is_number());
    assert!(body.get("refresh_token").is_none() || body["refresh_token"].is_null());
}

#[actix_rt::test]
async fn test_token_expired_code() {
    let mut oauth_db = Box::new(core::MockOauthDatabase::new());
    let user_db = Box::new(core::MockUserDatabase::new());

    oauth_db
        .expect_consume_oauth_session_by_code()
        .with(eq(CODE))
        .times(1)
        .returning(|c| Ok(expired_session(c)));

    let mut app = test::init_service(
        App::new()
            .app_data(Data::new(AppState::new(oauth_db, user_db, test_secrets(), common::test_config())))
            .route("/oauth2/token", web::post().to(token_endpoint)),
    )
    .await;

    let body = format!("grant_type=authorization_code&code={}&redirect_uri={}", CODE, REDIRECT);
    let req = test::TestRequest::post()
        .uri("/oauth2/token")
        .insert_header(("Authorization", VALID_AUTH))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(body)
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_rt::test]
async fn test_token_redirect_mismatch() {
    let mut oauth_db = Box::new(core::MockOauthDatabase::new());
    let user_db = Box::new(core::MockUserDatabase::new());

    oauth_db
        .expect_consume_oauth_session_by_code()
        .with(eq(CODE))
        .times(1)
        .returning(|c| Ok(future_session(c)));

    oauth_db
        .expect_fetch_client_config()
        .with(eq("test1"))
        .times(1)
        .returning(|_| Ok(test_client()));

    let mut app = test::init_service(
        App::new()
            .app_data(Data::new(AppState::new(oauth_db, user_db, test_secrets(), common::test_config())))
            .route("/oauth2/token", web::post().to(token_endpoint)),
    )
    .await;

    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}",
        CODE, "http://evil.example.com/callback"
    );
    let req = test::TestRequest::post()
        .uri("/oauth2/token")
        .insert_header(("Authorization", VALID_AUTH))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(body)
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_rt::test]
async fn test_token_invalid_credentials() {
    let mut oauth_db = Box::new(core::MockOauthDatabase::new());
    let user_db = Box::new(core::MockUserDatabase::new());

    oauth_db
        .expect_consume_oauth_session_by_code()
        .with(eq(CODE))
        .times(1)
        .returning(|c| Ok(future_session(c)));

    oauth_db
        .expect_fetch_client_config()
        .with(eq("test1"))
        .times(1)
        .returning(|_| Ok(test_client()));

    let mut app = test::init_service(
        App::new()
            .app_data(Data::new(AppState::new(oauth_db, user_db, test_secrets(), common::test_config())))
            .route("/oauth2/token", web::post().to(token_endpoint)),
    )
    .await;

    let body = format!("grant_type=authorization_code&code={}&redirect_uri={}", CODE, REDIRECT);
    let req = test::TestRequest::post()
        .uri("/oauth2/token")
        .insert_header(("Authorization", "Basic d3Jvbmc6Y3JlZHM=")) // wrong:creds
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(body)
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn test_token_unsupported_grant_type() {
    let mut app = test::init_service(
        App::new()
            .app_data(Data::new(mock_app_state()))
            .route("/oauth2/token", web::post().to(token_endpoint)),
    )
    .await;

    let body = format!("grant_type=refresh_token&code={}&redirect_uri={}", CODE, REDIRECT);
    let req = test::TestRequest::post()
        .uri("/oauth2/token")
        .insert_header(("Authorization", VALID_AUTH))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(body)
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_rt::test]
async fn test_token_code_not_found() {
    let mut oauth_db = Box::new(core::MockOauthDatabase::new());
    let user_db = Box::new(core::MockUserDatabase::new());

    oauth_db
        .expect_consume_oauth_session_by_code()
        .with(eq("unknown-code"))
        .times(1)
        .returning(|_| Err(core::error::InternalError::NotFound));

    let mut app = test::init_service(
        App::new()
            .app_data(Data::new(AppState::new(oauth_db, user_db, test_secrets(), common::test_config())))
            .route("/oauth2/token", web::post().to(token_endpoint)),
    )
    .await;

    let body = format!("grant_type=authorization_code&code=unknown-code&redirect_uri={}", REDIRECT);
    let req = test::TestRequest::post()
        .uri("/oauth2/token")
        .insert_header(("Authorization", VALID_AUTH))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(body)
        .to_request();

    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
