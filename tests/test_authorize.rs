mod common;

use actix_web::http::StatusCode;
use actix_web::{test, web, App};
use flipid::core::models::OauthClient;
use flipid::core::{self, load_encryption_material, AppState};
use flipid::oidc::authorize;
use mockall::predicate::*;

#[actix_rt::test]
async fn test_authorize_get_goto_login() {
    let mut oauth_db = Box::new(core::MockOauthDatabase::new());
    let user_db = Box::new(core::MockUserDatabase::new());
    oauth_db
        .expect_fetch_client_config()
        .with(eq("test1"))
        .times(1)
        .returning(|_| Ok(test_client1()));

    let mut app = test::init_service(
        App::new()
            .data(AppState::new(oauth_db, user_db, load_encryption_material(common::TEST_RSA_PEM), common::test_config()))
            .route("/authorize", web::get().to(authorize::auth_get)),
    )
    .await;
    let req = test::TestRequest::get()
        .uri("/authorize?response_type=code&client_id=test1&scope=openid&redirect_uri=http://localhost:8080/callback")
        .to_request();
    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::OK); // login page
}

#[actix_rt::test]
async fn test_authorize_get_no_params() {
    let mut app = test::init_service(App::new().data(mock_app_state()).route("/authorize", web::get().to(authorize::auth_get))).await;

    let req = test::TestRequest::with_uri("/authorize").to_request();
    let resp = test::call_service(&mut app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

fn mock_app_state() -> AppState {
    let oauth_db = Box::new(core::MockOauthDatabase::new());
    let user_db = Box::new(core::MockUserDatabase::new());
    AppState::new(oauth_db, user_db, load_encryption_material(common::TEST_RSA_PEM), common::test_config())
}

fn test_client1() -> OauthClient {
    OauthClient {
        id: "test1".into(),
        secret: "test1".into(),
        name: "Test1".into(),
        callback_url: vec!["http://localhost:8080/callback".into()],
        allowed_scopes: "openid profile email phone address".into(),
    }
}
