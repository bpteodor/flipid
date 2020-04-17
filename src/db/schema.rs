table! {
    granted_scopes (client_id, scope, user_id) {
        client_id -> Text,
        scope -> Text,
        user_id -> Text,
    }
}

table! {
    oauth_clients (id) {
        id -> Text,
        secret -> Text,
        name -> Text,
        callback_url -> Text,
        allowed_scopes -> Text,
    }
}

table! {
    oauth_scopes (name) {
        name -> Text,
        description -> Nullable<Text>,
    }
}

table! {
    oauth_sessions (auth_code) {
        auth_code -> Text,
        client_id -> Text,
        scopes -> Text,
        nonce -> Nullable<Text>,
        subject -> Text,
        expiration -> Timestamp,
        auth_time -> Nullable<Timestamp>,
    }
}

table! {
    oauth_tokens (token) {
        token -> Text,
        token_type -> Text,
        client_id -> Text,
        scopes -> Nullable<Text>,
        subject -> Nullable<Text>,
        expiration -> Nullable<BigInt>,
        created -> Timestamp,
    }
}

table! {
    users (id) {
        id -> Text,
        password -> Text,
        email -> Nullable<Text>,
        phone -> Nullable<Text>,
        given_name -> Text,
        family_name -> Text,
        preferred_display_name -> Nullable<Text>,
        address -> Nullable<Text>,
        birthdate -> Nullable<Text>,
        locale -> Nullable<Text>,
    }
}

joinable!(granted_scopes -> oauth_clients (client_id));
joinable!(granted_scopes -> oauth_scopes (scope));
joinable!(oauth_tokens -> oauth_clients (client_id));

allow_tables_to_appear_in_same_query!(
    granted_scopes,
    oauth_clients,
    oauth_scopes,
    oauth_sessions,
    oauth_tokens,
    users,
);
