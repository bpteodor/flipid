// TODO
struct OauthClient {
    redirect_uris: String, // REQUIRED json array
    response_types: String,
}

impl OauthClient {
    /// constructor with default values
    pub fn new(redirect_uris: String) -> Self {
        OauthClient {
            redirect_uris,
            response_types: "code".into(),
        }
    }
}
