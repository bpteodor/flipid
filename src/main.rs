use flipid::core::{self, load_encryption_material, AppState};
use flipid::{db, idp, oidc};

use actix_files as fs;
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::cookie::SameSite;
use actix_web::{cookie::Key, middleware, web, App, HttpRequest, HttpServer, Result};
use diesel::r2d2::ConnectionManager;
use diesel::SqliteConnection;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

/// https://openid.net/specs/openid-connect-core-1_0.html#ImplementationConsiderations
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let cfg = core::config::load("config/config.yaml").expect("failed to load config/config.yaml");

    if let Some(log_filter) = &cfg.core.log {
        std::env::set_var("RUST_LOG", log_filter);
    }

    // setup db connection
    let manager = ConnectionManager::<SqliteConnection>::new(&cfg.database.url);
    let pool = r2d2::Pool::builder().build(manager).expect("Failed to create connection pool.");
    let db = Box::new(db::DbSqlBridge(pool.clone()));

    let rsa_key = load_encryption_material(&cfg.oauth.id_token.rsa_key);
    let session_key = Key::generate(); //Key::from(cfg.auth.session_key.as_bytes());

    let addr = format!("{}:{}", &cfg.server.address, &cfg.server.port);
    let is_https = cfg.server.is_https();
    let tls_cfg = cfg.server.tls.clone();

    let srv = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState::new(db.clone(), db.clone(), rsa_key.clone(), cfg.clone())))
            .wrap(middleware::Logger::default()) // logging
            .wrap(init_cors(&cfg.server.cors))
            .wrap(init_session(session_key.clone(), &cfg))
            // static resources
            .service(fs::Files::new("/s", ".").show_files_listing())
            .route("/favicon.ico", web::get().to(favicon))
            // openid provider
            .route("/.well-known/openid-configuration", web::get().to(oidc::discovery::openid_config))
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

    log::info!("encrypted communication: {}", is_https);

    if !is_https {
        log::debug!("starting on port {}...", &addr);
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
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).expect(&("failed to load cert from ".to_string() + &tls.cert));
    builder
        .set_private_key_file(&tls.key, SslFiletype::PEM)
        .expect("failed to load server-key");
    builder.set_certificate_chain_file(&tls.cert).expect("failed to load server-cert");
    builder
}

fn init_session(secret_key: Key, cfg: &core::config::Config) -> SessionMiddleware<CookieSessionStore> {
    //log::debug!("session cookie: [{}] on {}", cfg.auth.secure_cookies, cfg.server.domain);

    SessionMiddleware::builder(CookieSessionStore::default(), secret_key)
        .cookie_name(cfg.auth.session_cookie.clone())
        .cookie_domain(cfg.server.domain.clone())
        //.cookie_path("/") // todo configurable
        .cookie_http_only(true)
        .cookie_same_site(SameSite::Strict)
        .cookie_secure(cfg.core.secure_cookies)
        .cookie_content_security(actix_session::config::CookieContentSecurity::Private)
        //.cookie_content_security(actix_session::config::CookieContentSecurity::Signed) // do not commit - INSECURE - for debug only
        .build()
}

fn init_cors(cors: &core::config::CorsConfig) -> middleware::DefaultHeaders {
    let mut headers = middleware::DefaultHeaders::new();
    for origin in &cors.allow_origin {
        headers = headers.add(("Access-Control-Allow-Origin", origin.as_str()));
    }
    for method in &cors.allow_methods {
        headers = headers.add(("Access-Control-Allow-Methods", method.as_str()));
    }
    for header in &cors.allow_headers {
        headers = headers.add(("Access-Control-Allow-Headers", header.as_str()));
    }
    headers.add(("Access-Control-Request-Headers", "X-Requested-With, accept, content-type"))
}
