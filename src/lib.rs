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

pub mod core;
pub mod db;
pub mod idp;
pub mod oidc;
