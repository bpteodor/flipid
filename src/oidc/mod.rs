pub mod authorize;
pub mod discovery;
pub mod dynamic_registration;
pub mod jwks;
pub mod token;
pub mod userinfo;

#[cfg(test)]
mod test_authorize;

/**
 * OAuth 2.0 Authorization Error Response
 */
#[derive(Serialize, Debug, Clone, Default)]
pub struct OauthError {
    pub error: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

impl OauthError {
    pub fn new<T: AsRef<str>>(error: T, descr: T) -> Self {
        OauthError {
            error: String::from(error.as_ref()),
            error_description: Some(descr.as_ref().into()),
            ..Default::default()
        }
    }

    pub fn of<T: AsRef<str>>(error: T) -> Self {
        OauthError {
            error: String::from(error.as_ref()),
            ..Default::default()
        }
    }
}
