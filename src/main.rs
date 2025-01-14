//#![allow(unused_variables)]
//#![allow(unused_imports)]
//#![allow(warnings)] //because of diesel (polluting the world, digital or analog)

extern crate actix_http;
extern crate actix_session;
extern crate actix_web;
extern crate futures;
extern crate tera;
extern crate url;
#[macro_use]
extern crate serde_derive;
extern crate env_logger;
extern crate serde;
extern crate serde_json;
extern crate serde_urlencoded;
#[macro_use]
extern crate log;
#[macro_use]
extern crate diesel;
extern crate base64;
extern crate chrono;
extern crate crypto_hash;
extern crate dotenv;
extern crate jsonwebtoken as jwt;
extern crate openssl;
extern crate r2d2;
extern crate rand;

mod config;
mod core;
mod db;
mod idp;
mod oidc;

use crate::core::AppState;
use actix_files as fs;
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::cookie::SameSite;
use actix_web::{cookie::Key, middleware, web, App, HttpRequest, HttpServer, Result};
use diesel::r2d2::ConnectionManager;
use diesel::SqliteConnection;
use dotenv::dotenv;
use jwt::EncodingKey;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

/// https://openid.net/specs/openid-connect-core-1_0.html#ImplementationConsiderations
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    env_logger::init();

    // setup db connection
    let manager = ConnectionManager::<SqliteConnection>::new(config::database_url());
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create connection pool.");
    let db = Box::new(db::DbSqlBridge(pool.clone()));
    let session_key = Key::generate();

    let srv = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState::new(
                db.clone(),
                db.clone(),
                load_encryption_material(),
            )))
            .wrap(middleware::Logger::default()) // logging
            .wrap(init_cors())
            .wrap(init_session(session_key.clone()))
            // static resources
            .service(fs::Files::new("/s", ".").show_files_listing())
            .route("/favicon.ico", web::get().to(favicon))
            // openid provider
            .route(
                "/.well-known/openid-configuration",
                web::get().to(oidc::discovery::openid_config),
            )
            .route("/op/authorize", web::get().to(oidc::authorize::auth_get))
            .route("/op/authorize", web::post().to(oidc::authorize::auth_post))
            .route("/op/token", web::post().to(oidc::token::token_endpoint))
            .route("/op/userinfo", web::get().to(oidc::userinfo::userinfo_endoint))
            .route("/op/userinfo", web::post().to(oidc::userinfo::userinfo_endoint))
            .route("/op/jwks", web::get().to(oidc::jwks::get_keys))
            // identity provider (should be customizable)
            .route("/idp/login", web::post().to(idp::login))
            .route("/idp/consent", web::post().to(idp::consent))
            .route("/idp/cancel", web::post().to(idp::cancel_login))
    });

    let addr = format!("0.0.0.0:{}", &config::port());
    info!("encrypted communication: {}", config::is_protocol_https());

    if !config::is_protocol_https() {
        debug!("starting on port {}...", &config::port());
        srv.bind(addr)
    } else {
        debug!("starting with SSL on port {}...", &config::port());
        let ssl = load_server_cert();
        srv.bind_openssl(addr, ssl)
    }
    .expect("occupied port")
    .run()
    .await
}

async fn favicon(_req: HttpRequest) -> Result<fs::NamedFile> {
    Ok(fs::NamedFile::open("static/favicon.ico")?)
}

fn load_encryption_material() -> EncodingKey {
    let pem: Vec<u8> = core::load_file(&config::oauth_rsa_pem()).expect("failed to read certificates");
    EncodingKey::from_rsa_pem(&pem).expect("failed to load key")
}

fn load_server_cert() -> openssl::ssl::SslAcceptorBuilder {
    info!("loading cert {}...", config::server_cert());
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())
        .expect(&("failed to load cert from ".to_string() + &config::server_cert()));
    builder
        .set_private_key_file(config::server_key(), SslFiletype::PEM)
        .expect("failed to load server-key");
    builder
        .set_certificate_chain_file(config::server_cert())
        .expect("failed to load server-cert");
    builder
}

fn init_session(secret_key: Key) -> SessionMiddleware<CookieSessionStore> {
    let base_uri = config::base_uri();
    debug!("secure cookies: {}", config::is_secure_cookies());

    // validate: domain is set
    base_uri.host().expect("invalid issuer: no domain");

    SessionMiddleware::builder(CookieSessionStore::default(), secret_key)
        .cookie_name("SID".to_string())
        .cookie_domain(base_uri.host().map(str::to_string))
        .cookie_path(base_uri.path().to_string())
        .cookie_http_only(true)
        .cookie_same_site(SameSite::Strict)
        .cookie_secure(config::is_secure_cookies())
        .cookie_content_security(actix_session::config::CookieContentSecurity::Private)
        //.cookie_content_security(actix_session::config::CookieContentSecurity::Signed) // do not commit - INSECURE - for debug only
        .build()
}

fn init_cors() -> middleware::DefaultHeaders {
    // TODO: move to config
    middleware::DefaultHeaders::new() // CORS
        .add(("Access-Control-Allow-Origin", "https://fonts.gstatic.com"))
        .add(("Access-Control-Allow-Methods", "GET"))
        .add(("Access-Control-Allow-Headers", "Content-Type"))
        .add((
            "Access-Control-Request-Headers",
            "X-Requested-With, accept, content-type",
        ))
}
