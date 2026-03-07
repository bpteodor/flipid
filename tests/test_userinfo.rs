use flipid::core::{self, load_encryption_material, AppState};
use flipid::core::models::{OauthToken, User};
use flipid::oidc::userinfo::userinfo_endoint;
use actix_web::http::StatusCode;
use actix_web::{test, web, App};
use mockall::predicate::*;

const ACCESS_TOKEN: &str = "test-access-token-abc";

fn token_with_scopes(scopes: &str) -> OauthToken {
    OauthToken {
        token: ACCESS_TOKEN.into(),
        token_type: "access".into(),
        client_id: "test1".into(),
        scopes: Some(scopes.into()),
        subject: Some("user@example.com".into()),
        expiration: None,
        created: chrono::Utc::now().naive_utc(),
    }
}

fn test_user() -> User {
    User {
        id: "user@example.com".into(),
        password: "hashed".into(),
        email: Some("user@example.com".into()),
        phone: Some("+1234567890".into()),
        given_name: "John".into(),
        family_name: "Doe".into(),
        preferred_display_name: None,
        address: Some("123 Main St".into()),
        birthdate: Some("1990-01-01".into()),
        locale: Some("en-US".into()),
    }
}

fn bearer(token: &str) -> String {
    format!("Bearer {}", token)
}

async fn call_userinfo(
    oauth_db: Box<core::MockOauthDatabase>,
    user_db: Box<core::MockUserDatabase>,
    auth_header: Option<&str>,
) -> actix_web::dev::ServiceResponse {
    dotenv::from_filename("tests/resources/.env").ok();
    let mut app = test::init_service(
        App::new()
            .data(core::AppState::new(oauth_db, user_db, load_encryption_material()))
            .route("/op/userinfo", web::get().to(userinfo_endoint)),
    )
    .await;

    let mut req = test::TestRequest::get().uri("/op/userinfo");
    if let Some(h) = auth_header {
        req = req.insert_header(("Authorization", h));
    }
    test::call_service(&mut app, req.to_request()).await
}

#[actix_rt::test]
async fn test_userinfo_happy_path() {
    let mut oauth_db = Box::new(core::MockOauthDatabase::new());
    let mut user_db = Box::new(core::MockUserDatabase::new());

    oauth_db
        .expect_load_token_data()
        .with(eq(ACCESS_TOKEN))
        .times(1)
        .returning(|_| Ok(token_with_scopes("openid profile email")));

    user_db
        .expect_fetch_user()
        .with(eq("user@example.com"))
        .times(1)
        .returning(|_| Ok(test_user()));

    let resp = call_userinfo(oauth_db, user_db, Some(&bearer(ACCESS_TOKEN))).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["sub"], "user@example.com");
    assert_eq!(body["given_name"], "John");
    assert_eq!(body["family_name"], "Doe");
    assert_eq!(body["email"], "user@example.com");
    assert_eq!(body["email_verified"], false);
    assert!(body.get("phone_number").is_none());
    assert!(body.get("address").is_none());
}

#[actix_rt::test]
async fn test_userinfo_all_scopes() {
    let mut oauth_db = Box::new(core::MockOauthDatabase::new());
    let mut user_db = Box::new(core::MockUserDatabase::new());

    oauth_db
        .expect_load_token_data()
        .with(eq(ACCESS_TOKEN))
        .times(1)
        .returning(|_| Ok(token_with_scopes("openid profile email phone address")));

    user_db
        .expect_fetch_user()
        .with(eq("user@example.com"))
        .times(1)
        .returning(|_| Ok(test_user()));

    let resp = call_userinfo(oauth_db, user_db, Some(&bearer(ACCESS_TOKEN))).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["sub"], "user@example.com");
    assert_eq!(body["email"], "user@example.com");
    assert_eq!(body["phone_number"], "+1234567890");
    assert_eq!(body["address"], "123 Main St");
    assert_eq!(body["locale"], "en-US");
    assert_eq!(body["birthdate"], "1990-01-01");
}

#[actix_rt::test]
async fn test_userinfo_no_auth_header() {
    let oauth_db = Box::new(core::MockOauthDatabase::new());
    let user_db = Box::new(core::MockUserDatabase::new());

    let resp = call_userinfo(oauth_db, user_db, None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn test_userinfo_invalid_token_type() {
    let mut oauth_db = Box::new(core::MockOauthDatabase::new());
    let user_db = Box::new(core::MockUserDatabase::new());

    oauth_db
        .expect_load_token_data()
        .with(eq(ACCESS_TOKEN))
        .times(1)
        .returning(|_| {
            Ok(OauthToken {
                token: ACCESS_TOKEN.into(),
                token_type: "id".into(),
                client_id: "test1".into(),
                scopes: Some("openid".into()),
                subject: Some("user@example.com".into()),
                expiration: None,
                created: chrono::Utc::now().naive_utc(),
            })
        });

    let resp = call_userinfo(oauth_db, user_db, Some(&bearer(ACCESS_TOKEN))).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn test_userinfo_missing_openid_scope() {
    let mut oauth_db = Box::new(core::MockOauthDatabase::new());
    let user_db = Box::new(core::MockUserDatabase::new());

    oauth_db
        .expect_load_token_data()
        .with(eq(ACCESS_TOKEN))
        .times(1)
        .returning(|_| Ok(token_with_scopes("profile email")));

    let resp = call_userinfo(oauth_db, user_db, Some(&bearer(ACCESS_TOKEN))).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn test_userinfo_token_not_found() {
    let mut oauth_db = Box::new(core::MockOauthDatabase::new());
    let user_db = Box::new(core::MockUserDatabase::new());

    oauth_db
        .expect_load_token_data()
        .with(eq(ACCESS_TOKEN))
        .times(1)
        .returning(|_| Err(core::error::InternalError::NotFound));

    let resp = call_userinfo(oauth_db, user_db, Some(&bearer(ACCESS_TOKEN))).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[actix_rt::test]
async fn test_userinfo_invalid_bearer_format() {
    let oauth_db = Box::new(core::MockOauthDatabase::new());
    let user_db = Box::new(core::MockUserDatabase::new());

    let resp = call_userinfo(oauth_db, user_db, Some("Token abc123")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
