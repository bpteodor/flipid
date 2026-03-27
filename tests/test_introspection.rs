mod common;

use actix_web::http::StatusCode;
use actix_web::web::Data;
use actix_web::{test, web, App};
use flipid::core::models::{OauthClient, OauthToken};
use flipid::core::{self, basic_auth, AppState, Secrets};
use flipid::oidc::introspection::introspect;
use mockall::predicate::*;
use std::sync::Arc;

const ACCESS_TOKEN: &str = "test-access-token-abc";
const CLIENT_ID: &str = "test1";
const CLIENT_SECRET: &str = "secret";

fn test_client() -> OauthClient {
    let hash = bcrypt::hash(CLIENT_SECRET, 4).unwrap();
    OauthClient {
        id: CLIENT_ID.into(),
        secret: format!("{{BCRYPT}}{}", hash),
        name: "Test1".into(),
        callback_url: vec!["http://localhost:8080/callback".into()],
        allowed_scopes: "openid profile email".into(),
    }
}

fn active_token() -> OauthToken {
    OauthToken {
        token: ACCESS_TOKEN.into(),
        token_type: "access".into(),
        client_id: CLIENT_ID.into(),
        scopes: Some("openid profile".into()),
        subject: Some("user@example.com".into()),
        expiration: None,
        created: chrono::Utc::now().naive_utc(),
    }
}

fn expiring_token(secs_from_now: i64) -> OauthToken {
    let created = chrono::Utc::now().naive_utc() - chrono::Duration::seconds(10);
    let expiration = 10 + secs_from_now; // created + expiration = now + secs_from_now
    OauthToken {
        token: ACCESS_TOKEN.into(),
        token_type: "access".into(),
        client_id: CLIENT_ID.into(),
        scopes: Some("openid".into()),
        subject: Some("user@example.com".into()),
        expiration: Some(expiration),
        created,
    }
}

async fn call_introspect(
    oauth_db: Box<core::MockOauthDatabase>,
    user_db: Box<core::MockUserDatabase>,
    auth_header: Option<&str>,
    body: &str,
) -> actix_web::dev::ServiceResponse {
    let mut app = test::init_service(
        App::new()
            .app_data(Data::new(AppState::new(
                common::test_key(),
                oauth_db,
                user_db,
                Arc::new(Secrets::load(&common::test_config().secrets).expect("test secrets")),
                common::test_config(),
            )))
            .route("/oauth2/token_info", web::post().to(introspect)),
    )
    .await;

    let mut req = test::TestRequest::post()
        .uri("/oauth2/token_info")
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(body.to_owned());
    if let Some(h) = auth_header {
        req = req.insert_header(("Authorization", h));
    }
    test::call_service(&mut app, req.to_request()).await
}

fn valid_auth() -> String {
    basic_auth(CLIENT_ID, CLIENT_SECRET)
}

fn token_body(token: &str) -> String {
    format!("token={}", token)
}

#[actix_rt::test]
async fn test_introspect_happy_path() {
    let mut oauth_db = Box::new(core::MockOauthDatabase::new());
    let user_db = Box::new(core::MockUserDatabase::new());

    oauth_db
        .expect_fetch_client_config()
        .with(eq(CLIENT_ID))
        .times(1)
        .returning(|_| Ok(test_client()));

    oauth_db
        .expect_load_token_data()
        .with(eq(ACCESS_TOKEN))
        .times(1)
        .returning(|_| Ok(active_token()));

    let auth = valid_auth();
    let resp = call_introspect(oauth_db, user_db, Some(&auth), &token_body(ACCESS_TOKEN)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["active"], true);
    assert_eq!(body["sub"], "user@example.com");
    assert_eq!(body["client_id"], CLIENT_ID);
    assert_eq!(body["scope"], "openid profile");
    assert_eq!(body["token_type"], "access");
    assert!(body["iat"].is_number());
    assert!(body.get("exp").is_none()); // no expiration set on active_token
}

#[actix_rt::test]
async fn test_introspect_expired_token() {
    let mut oauth_db = Box::new(core::MockOauthDatabase::new());
    let user_db = Box::new(core::MockUserDatabase::new());

    oauth_db
        .expect_fetch_client_config()
        .with(eq(CLIENT_ID))
        .times(1)
        .returning(|_| Ok(test_client()));

    oauth_db
        .expect_load_token_data()
        .with(eq(ACCESS_TOKEN))
        .times(1)
        .returning(|_| Ok(expiring_token(-1))); // expired 1 second ago

    let auth = valid_auth();
    let resp = call_introspect(oauth_db, user_db, Some(&auth), &token_body(ACCESS_TOKEN)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["active"], false);
    assert!(body.get("sub").is_none());
}

#[actix_rt::test]
async fn test_introspect_token_not_found() {
    let mut oauth_db = Box::new(core::MockOauthDatabase::new());
    let user_db = Box::new(core::MockUserDatabase::new());

    oauth_db
        .expect_fetch_client_config()
        .with(eq(CLIENT_ID))
        .times(1)
        .returning(|_| Ok(test_client()));

    oauth_db
        .expect_load_token_data()
        .with(eq("unknown-token"))
        .times(1)
        .returning(|_| Err(core::error::InternalError::NotFound));

    let auth = valid_auth();
    let resp = call_introspect(oauth_db, user_db, Some(&auth), "token=unknown-token").await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["active"], false);
}

#[actix_rt::test]
async fn test_introspect_no_auth_header() {
    let oauth_db = Box::new(core::MockOauthDatabase::new());
    let user_db = Box::new(core::MockUserDatabase::new());

    let resp = call_introspect(oauth_db, user_db, None, &token_body(ACCESS_TOKEN)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn test_introspect_invalid_credentials() {
    let mut oauth_db = Box::new(core::MockOauthDatabase::new());
    let user_db = Box::new(core::MockUserDatabase::new());

    oauth_db
        .expect_fetch_client_config()
        .with(eq(CLIENT_ID))
        .times(1)
        .returning(|_| Ok(test_client()));

    let wrong_auth = basic_auth(CLIENT_ID, "wrong-secret");
    let resp = call_introspect(oauth_db, user_db, Some(&wrong_auth), &token_body(ACCESS_TOKEN)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn test_introspect_unsupported_token_type_hint() {
    let mut oauth_db = Box::new(core::MockOauthDatabase::new());
    let user_db = Box::new(core::MockUserDatabase::new());

    oauth_db.expect_fetch_client_config().with(eq(CLIENT_ID)).times(0); // credential check should not be reached

    let auth = valid_auth();
    let resp = call_introspect(
        oauth_db,
        user_db,
        Some(&auth),
        &format!("token={}&token_type_hint=refresh_token", ACCESS_TOKEN),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["active"], false);
}

#[actix_rt::test]
async fn test_introspect_active_token_with_expiration() {
    let mut oauth_db = Box::new(core::MockOauthDatabase::new());
    let user_db = Box::new(core::MockUserDatabase::new());

    oauth_db
        .expect_fetch_client_config()
        .with(eq(CLIENT_ID))
        .times(1)
        .returning(|_| Ok(test_client()));

    oauth_db
        .expect_load_token_data()
        .with(eq(ACCESS_TOKEN))
        .times(1)
        .returning(|_| Ok(expiring_token(3600))); // expires in 1 hour

    let auth = valid_auth();
    let resp = call_introspect(oauth_db, user_db, Some(&auth), &token_body(ACCESS_TOKEN)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["active"], true);
    assert!(body["exp"].is_number());
    assert!(body["iat"].is_number());
}
