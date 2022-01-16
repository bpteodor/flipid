use super::core::error::InternalError;
use super::core::error::InternalError::{ConnectionError, NotFound};
use super::core::models;
use super::core::{OauthDatabase, UserDatabase};
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::result::Error::QueryBuilderError;
use std::collections::HashSet;

//pub mod models;
pub mod schema;

/// db query bridge
#[derive(Clone)]
pub struct DbSqlBridge(pub Pool<ConnectionManager<SqliteConnection>>);

macro_rules! get_conn {
    ( $x:expr ) => {
        &$x.0.get().map_err(|_| ConnectionError)?
    };
}

impl OauthDatabase for DbSqlBridge {
    fn fetch_client_config(&self, client_id: &str) -> QueryResult<models::OauthClient> {
        use self::schema::oauth_clients::dsl::*;
        trace!("fetch_client_config({})...", client_id);

        let conn = self.0.get().map_err(|e| QueryBuilderError(Box::from(e)))?;
        let item = oauth_clients.find(client_id).first::<models::OauthClient>(&conn)?;

        trace!("client-config: {:?}", item);
        Ok(item)
    }

    // TODO:- delete expired sessions
    fn save_oauth_session(&self, session: models::OauthSession) -> Result<(), InternalError> {
        trace!("save_oauth_session({:?})...", session);
        diesel::insert_into(schema::oauth_sessions::table)
            .values(&session)
            .execute(get_conn!(self))
            .map_err(|_| InternalError::query_fail("error saving new oauth session"))?;
        Ok(())
    }

    /*fn fetch_oauth_session(&self, sid: &str) -> Result<models::OauthSession, AppError> {
        use self::schema::oauth_sessions::dsl::*;

        let conn = &self
            .0
            .get()
            .map_err(|e| InternalError("error getting db connection".into(), Box::new(e)))?;

        let mut items = oauth_sessions
            .filter(id.eq(sid))
            .load::<models::OauthSession>(conn)
            .map_err(|e| InternalError(format!("error loading oauth session {}", sid), Box::new(e)))?;

        if items.len() < 1 {
            return Err(AppError::NotFound("session not found".into()));
        }

        let item = items.pop().unwrap();
        debug!("oauthSession({}) = {:?}", sid, &item);
        Ok(item)
    }*/

    fn consume_oauth_session_by_code(&self, code: &str) -> Result<models::OauthSession, InternalError> {
        use self::schema::oauth_sessions::dsl::*;
        trace!("fetch_oauth_session_by_code({})...", code);

        let conn = get_conn!(self);
        let mut items = oauth_sessions
            .filter(auth_code.eq(code))
            .load::<models::OauthSession>(conn)
            .map_err(|_| InternalError::query_fail(&format!("error loading oauth session by code {}", code)))?;

        diesel::delete(oauth_sessions)
            .filter(auth_code.eq(code))
            .execute(conn)
            .map_err(|_| InternalError::query_fail(&format!("error deleting oauth session by code {}", code)))?;

        if items.len() < 1 {
            return Err(NotFound);
        }

        let item = items.pop().unwrap();
        debug!("oauthSession({}) = {:?}", code, &item);
        Ok(item)
    }

    /*fn set_code_to_session(&self, sid: &str, code: &str, code_exp: &NaiveDateTime) -> Result<(), AppError> {
        use self::schema::oauth_sessions::dsl::*;
        debug!("<{}> saving code {} {}", sid, code, code_exp);

        let conn = &self
            .0
            .get()
            .map_err(|e| InternalError("error getting db connection".into(), Box::new(e)))?;

        let now = NaiveDateTime::from_timestamp(Utc::now().timestamp(), 0);

        diesel::update(oauth_sessions.find(sid))
            .set((auth_code.eq(code), auth_code_exp.eq(code_exp), last_change.eq(now)))
            .execute(conn);

        Ok(())
    }*/

    /*fn set_token_to_session(&self, sid: &str, token: &str, token_exp: &NaiveDateTime) -> Result<(), AppError> {
        use self::schema::oauth_sessions::dsl::*;
        debug!("<{}> saving token {} {}", sid, token, token_exp);

        let conn = &self
            .0
            .get()
            .map_err(|e| InternalError("error getting db connection".into(), Box::new(e)))?;

        let now = NaiveDateTime::from_timestamp(Utc::now().timestamp(), 0);

        diesel::update(oauth_sessions.find(sid))
            .set((
                auth_token.eq(token),
                auth_token_exp.eq(auth_token_exp),
                last_change.eq(now),
            ))
            .execute(conn);

        Ok(())
    }
    fn delete_oauth_session(&self, sid: &str) -> Result<(), AppError> {
        use self::schema::oauth_sessions::dsl::*;
        debug!("<{}> deleting oauth session...", sid);

        let conn = &self
            .0
            .get()
            .map_err(|e| InternalError("error getting db connection".into(), Box::new(e)))?;

        diesel::delete(oauth_sessions.find(sid)).execute(conn);

        Ok(())
    }*/

    fn save_oauth_token(&self, data: &models::OauthToken) -> Result<(), InternalError> {
        use self::schema::oauth_tokens::dsl::*;
        trace!("saving token {:?}", data);

        diesel::insert_into(oauth_tokens)
            .values(data)
            .execute(get_conn!(self))
            .map_err(|_| InternalError::query_fail("error saving new oauth token"))?;
        Ok(())
    }

    fn load_token_data(&self, t: &str) -> Result<models::OauthToken, InternalError> {
        use self::schema::oauth_tokens::dsl::*;
        trace!("load_token_data({})...", t);

        let mut items = oauth_tokens
            .filter(token.eq(t))
            .load::<models::OauthToken>(get_conn!(self))
            .map_err(|_| InternalError::query_fail("error loading token"))?;

        if items.len() < 1 {
            return Err(NotFound);
        }

        let item = items.pop().unwrap();
        debug!("oauthToken({}) = {:?}", t, &item);
        Ok(item)
    }
}

impl UserDatabase for DbSqlBridge {
    fn login(&self, uid: &str, pass: &str) -> Result<models::User, InternalError> {
        use self::schema::users::dsl::*;
        debug!("login(user: '{}')...", uid);
        trace!("pass: {}", pass); // delete this

        let mut items = users
            .filter(id.eq(uid))
            .filter(password.eq(pass))
            .load::<models::User>(get_conn!(self))
            .map_err(|e| InternalError::query_fail(&format!("error loading user {}: {:?}", uid, e)))?;

        if items.len() < 1 {
            return Err(NotFound);
        }

        let item = items.pop().unwrap();
        debug!("user({}) = {:?}", uid, &item);
        Ok(item)
    }

    fn fetch_user(&self, uid: &str) -> Result<models::User, InternalError> {
        use self::schema::users::dsl::*;
        trace!("login({})...", uid);

        let mut items = users
            .filter(id.eq(uid))
            .load::<models::User>(get_conn!(self))
            .map_err(|_| InternalError::query_fail(&format!("error loading user {}", uid)))?;

        if items.len() < 1 {
            return Err(NotFound);
        }

        let item = items.pop().unwrap();
        debug!("user({}) = {:?}", uid, &item);
        Ok(item)
    }

    fn fetch_granted_scopes(&self, cid: &str, uid: &str) -> Result<HashSet<String>, InternalError> {
        use self::schema::granted_scopes::dsl::*;
        trace!("fetch_granted_scopes({}, {})...", cid, uid);

        let items = granted_scopes
            .select(scope)
            .filter(user_id.eq(uid))
            .filter(client_id.eq(cid))
            .load::<String>(get_conn!(self))
            .map_err(|_| InternalError::query_fail(&format!("error loading scopes [cid: {}, uid: {}]", cid, uid)))?;

        debug!("loaded scopes(cid: {}, uid: {}) = {:?}", cid, uid, &items);
        Ok(items.into_iter().collect())
    }

    fn save_granted_scopes(&self, uid: &str, cid: &str, scopes: &Vec<String>) -> Result<(), InternalError> {
        use self::schema::granted_scopes::dsl::*;
        trace!("save_granted_scopes({}, {}, {:?})...", uid, cid, scopes);

        //let conn: &SqliteConnection = &self.0.get().map_err(|e| InternalError::ConnectionError)?; TODO
        let conn: &SqliteConnection = &self.0.get().unwrap();

        let mut values = Vec::new();
        for s in scopes {
            values.push((client_id.eq(cid), scope.eq(s), user_id.eq(uid)));
        }

        let inserted = diesel::insert_into(granted_scopes)
            .values(&values)
            .execute(conn)
            .map_err(|_| InternalError::query_fail("error saving new oauth session"))?;

        debug!("saved {} granted-scopes to user {}: {:?}", inserted, uid, scopes);
        Ok(())
    }
}

/*pub fn create_user(& self, msg: CreateUser) -> Result<models::User, String> {
    use self::schema::users::dsl::*;

    let uuid = format!("{}", uuid::Uuid::new_v4());
    let new_user = models::NewUser {
        id: &uuid,
        name: &msg.name,
    };

    let conn: &SqliteConnection = &self.0.get().unwrap();

    diesel::insert_into(users)
        .values(&new_user)
        .execute(conn)
        .map_err(|_| "Error inserting person")?;

    let mut items = users
        .filter(id.eq(&uuid))
        .load::<models::User>(conn)
        .map_err(|_| "Error loading person")?;

    Ok(items.pop().unwrap())
}*/
