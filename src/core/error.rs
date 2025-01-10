use actix_web::{http::StatusCode, HttpResponse, HttpResponseBuilder, ResponseError};
use failure::Fail;

/// displayable error
#[derive(Fail, Debug)]
pub enum AppError {
    #[fail(display = "{}", msg)]
    ValidationError { msg: String },
    #[fail(display = "{}", msg)]
    InvalidAuthSession { msg: String },
    #[fail(display = "An internal error occurred. Please try again later.")]
    InternalError,
    #[fail(display = "Not Authorized")]
    Unauthorized, // TODO must set www-auth header
    //#[fail(display = "Operation not allowed.")]
    //Forbidden,
    #[fail(display = "not found")]
    NotFound, // { item: String },
}

impl AppError {
    pub fn bad_req<T: AsRef<str>>(m: T) -> Self {
        AppError::ValidationError {
            msg: String::from(m.as_ref()),
        }
    }
    pub fn bad_auth_session(m: &str) -> Self {
        AppError::InvalidAuthSession { msg: String::from(m) }
    }
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        info!("{:?}", self);
        HttpResponseBuilder::new(self.status_code())
            .content_type("text/html; charset=utf-8")
            .body(self.to_string())
    }
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::ValidationError { msg: _ } => StatusCode::BAD_REQUEST,
            AppError::InvalidAuthSession { msg: _ } => StatusCode::BAD_REQUEST,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            //AppError::Forbidden => StatusCode::FORBIDDEN,
            AppError::NotFound => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

///
#[derive(Fail, Debug)]
pub enum InternalError {
    #[fail(display = "db connection error")]
    ConnectionError,
    #[fail(display = "query: {}", msg)]
    QueryError { msg: String },
    #[fail(display = "not found")]
    NotFound,
    #[fail(display = "session error")]
    SessionError,
}

impl InternalError {
    pub(crate) fn query_fail(m: &str) -> Self {
        InternalError::QueryError { msg: String::from(m) }
    }

    pub(crate) fn to_user(&self) -> AppError {
        error!("{}", self);
        match *self {
            InternalError::NotFound => AppError::NotFound,
            _ => AppError::InternalError,
        }
    }
}

impl ResponseError for InternalError {
    fn error_response(&self) -> HttpResponse {
        error!("{}", self);
        HttpResponseBuilder::new(self.status_code())
            .content_type("text/html; charset=utf-8")
            .body(self.to_string())
    }

    fn status_code(&self) -> StatusCode {
        match *self {
            InternalError::NotFound => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
