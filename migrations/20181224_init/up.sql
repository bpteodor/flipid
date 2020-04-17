-- OpenID Connect db

CREATE TABLE oauth_clients (
  id VARCHAR NOT NULL PRIMARY KEY,
  secret VARCHAR NOT NULL,
  name VARCHAR NOT NULL,
  callback_url VARCHAR NOT NULL,
  allowed_scopes VARCHAR NOT NULL
);

CREATE TABLE oauth_scopes (
  name VARCHAR NOT NULL PRIMARY KEY,
  description VARCHAR
);

CREATE TABLE oauth_sessions (
  auth_code VARCHAR NOT NULL PRIMARY KEY,
  client_id VARCHAR not null,
  scopes VARCHAR NOT NULL,
  nonce VARCHAR,
  subject VARCHAR not null,
  expiration TIMESTAMP not null,
  auth_time Timestamp
);

CREATE TABLE oauth_tokens(
  token VARCHAR NOT NULL PRIMARY KEY,
  token_type VARCHAR not null,
  client_id VARCHAR not null,
  scopes VARCHAR,
  subject VARCHAR, --fk
  expiration BIGINT, --seconds after creation
  created Timestamp NOT null,
    FOREIGN KEY (client_id) REFERENCES oauth_clients(id)
);

CREATE UNIQUE INDEX idx_oauth_sessions_auth_code ON oauth_sessions (client_id, auth_code);
CREATE UNIQUE INDEX idx_oauth_sessions_auth_token ON oauth_tokens (token);

-- Users database

CREATE TABLE users (
  id VARCHAR NOT NULL PRIMARY KEY,
  password VARCHAR NOT NULL,
  email VARCHAR,
  phone VARCHAR,
  -- profile
  given_name VARCHAR NOT NULL,
  family_name VARCHAR NOT NULL,
  preferred_display_name VARCHAR,
  address VARCHAR, -- free text
  birthdate VARCHAR, -- format "YYYY-MM-DD"
  locale VARCHAR -- format: "en-US"
);

CREATE TABLE granted_scopes (
  --id INTEGER NOT NULL PRIMARY KEY,
  client_id VARCHAR NOT NULL,
  scope VARCHAR NOT NULL,
  user_id VARCHAR NOT NULL,
  PRIMARY KEY (client_id, user_id, scope)
  FOREIGN KEY (client_id) REFERENCES oauth_clients(id),
  FOREIGN KEY (scope) REFERENCES oauth_scopes(name) --, FOREIGN KEY (user_id) REFERENCES users(id) ?different db?
);

-- TEST data


INSERT INTO oauth_scopes(name) VALUES('openid'), ('profile'), ('email');
INSERT INTO oauth_clients (id, secret, name, callback_url, allowed_scopes) VALUES
  ('test-app1', 'secret', 'TestApp1', '["http://localhost:8080/callback"]', 'openid profile email phone address'),
  ('test-app2', 'secret', 'TestApp2', '["http://localhost:8080/oidc_client_vaadin_war/cb"]', 'openid profile'),
  ('oidcdebugger', 'oidcdebugger', 'oidc Debugger', '["https://oidcdebugger.com/debug"]', 'openid profile email'),
  ('cert', 'cert123!', 'cert', '["https://op.certification.openid.net:62156/authz_cb","https://op.certification.openid.net:62156/authz_post"]', 'openid profile email'),
  ('cert2', 'cert123!', 'cert2', '["https://op.certification.openid.net:61505/authz_cb","https://op.certification.openid.net:61505/authz_post"]', 'openid profile email phone'),
  ('cert3', 'theLastTry', 'cert3', '["https://op.certification.openid.net:62158/authz_cb","https://op.certification.openid.net:62158/authz_post"]', 'openid profile email phone')
;
-- pass is 'test'
INSERT INTO users VALUES 
('max', '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', 
  'max@test.local', "+401234567", 'Max', 'Muster', 'Maxy', 'Stuttgart', '1980-04-01', 'de-DE'),
('rik', '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', 
  'erika@test.local', "+49938568", 'Erika', 'Muster', 'rik', 'Berlin', '1969-03-07', 'en-DE');
