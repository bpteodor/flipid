use flipid::core::{self, AppState, Secrets};
use flipid::{db, idp, oidc};
use std::sync::Arc;

use actix_cors::Cors;
use actix_files as fs;
use actix_web::cookie::Key;
use actix_web::{middleware, web, App, HttpRequest, HttpServer, Result};
use diesel::r2d2::ConnectionManager;
use diesel::SqliteConnection;
use dotenv::dotenv;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

/// https://openid.net/specs/openid-connect-core-1_0.html#ImplementationConsiderations
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    let cfg = core::config::load("config/config.yaml").expect("failed to load config/config.yaml");

    // setup db connection
    let manager = ConnectionManager::<SqliteConnection>::new(&cfg.database.url);
    let pool = r2d2::Pool::builder().build(manager).expect("Failed to create connection pool.");
    let db = Box::new(db::DbSqlBridge(pool.clone()));

    let secrets = Arc::new(Secrets::load(&cfg.secrets).expect("failed to load secrets"));
    //let session_key = Key::from(cfg.auth.session_key.as_bytes()); // Key::generate();

    let addr = format!("{}:{}", &cfg.server.address, &cfg.server.port);
    let is_https = cfg.server.is_https();
    let tls_cfg = cfg.server.tls.clone();

    let srv = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState::new(
                Key::generate(),
                db.clone(),
                db.clone(),
                secrets.clone(),
                cfg.clone(),
            )))
            .wrap(middleware::Logger::default()) // logging
            //.wrap(init_session(session_key.clone(), &cfg))
            // static resources
            .service(fs::Files::new("/s", ".").show_files_listing())
            .route("/favicon.ico", web::get().to(favicon))
            // well-known endpoints: open to all origins
            .service(
                web::scope("/.well-known")
                    .wrap(Cors::permissive())
                    .route("/openid-configuration", web::get().to(oidc::discovery::openid_config))
                    .route("/jwks.json", web::get().to(oidc::jwks::get_keys)),
            )
            // all other endpoints: configured CORS
            .service(
                web::scope("")
                    .wrap(init_cors(&cfg.server.cors))
                    .route("/oauth2/authorize", web::get().to(oidc::authorize::auth_get))
                    .route("/oauth2/authorize", web::post().to(oidc::authorize::auth_post))
                    .route("/oauth2/token", web::post().to(oidc::token::token_endpoint))
                    .route("/oauth2/token_info", web::post().to(oidc::introspection::introspect))
                    .route("/oauth2/user_info", web::get().to(oidc::userinfo::userinfo_endpoint))
                    .route("/oauth2/user_info", web::post().to(oidc::userinfo::userinfo_endpoint))
                    // identity provider (should be customizable)
                    .route("/idp/login", web::post().to(idp::login))
                    .route("/idp/consent", web::post().to(idp::consent))
                    .route("/idp/cancel", web::post().to(idp::cancel_login)),
            )
    });

    log::info!("encrypted communication: {}", is_https);

    if !is_https {
        log::info!("starting on port {}...", &addr);
        srv.bind(addr)
    } else {
        log::debug!("starting with SSL on port {}...", &addr);
        let ssl = load_server_cert(tls_cfg.as_ref().expect("tls config required for https"));
        srv.bind_openssl(addr, ssl)
    }
    .expect("occupied port")
    .run()
    .await
}

async fn favicon(_req: HttpRequest) -> Result<fs::NamedFile> {
    Ok(fs::NamedFile::open("static/favicon.ico")?)
}

fn load_server_cert(tls: &core::config::TlsConfig) -> openssl::ssl::SslAcceptorBuilder {
    log::info!("loading cert {}...", tls.cert);
    let mut builder =
        SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap_or_else(|_| panic!("{}", ("failed to load cert from ".to_string() + &tls.cert)));
    builder
        .set_private_key_file(&tls.key, SslFiletype::PEM)
        .expect("failed to load server-key");
    builder.set_certificate_chain_file(&tls.cert).expect("failed to load server-cert");
    builder
}

/*fn init_session(secret_key: Key, cfg: &core::config::Config) -> SessionMiddleware<CookieSessionStore> {
    //log::debug!("session cookie: [{}] on {}", cfg.auth.secure_cookies, cfg.server.domain);

    SessionMiddleware::builder(CookieSessionStore::default(), secret_key)
        .cookie_name(cfg.auth.sso_session.clone())
        .cookie_domain(cfg.server.domain.clone())
        //.cookie_path("/") // todo configurable
        .cookie_http_only(true)
        .cookie_same_site(SameSite::Strict)
        .cookie_secure(cfg.core.secure_cookies)
        .cookie_content_security(actix_session::config::CookieContentSecurity::Private)
        //.cookie_content_security(actix_session::config::CookieContentSecurity::Signed) // do not commit - INSECURE - for debug only
        .build()
}*/

fn init_cors(cors_cfg: &core::config::CorsConfig) -> Cors {
    let mut cors = Cors::default();
    for origin in &cors_cfg.allow_origin {
        cors = cors.allowed_origin(origin.as_str());
    }
    if !cors_cfg.allow_methods.is_empty() {
        cors = cors.allowed_methods(
            cors_cfg
                .allow_methods
                .iter()
                .filter_map(|m| m.parse::<actix_web::http::Method>().ok())
                .collect::<Vec<_>>(),
        );
    }
    if !cors_cfg.allow_headers.is_empty() {
        cors = cors.allowed_headers(
            cors_cfg
                .allow_headers
                .iter()
                .filter_map(|h| h.parse::<actix_web::http::header::HeaderName>().ok())
                .collect::<Vec<_>>(),
        );
    }
    cors
}
