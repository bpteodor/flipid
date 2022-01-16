# FlipID

[![Build Status](https://travis-ci.org/bpteodor/flipid.svg?branch=master)](https://travis-ci.org/bpteodor/flipid)
[![License: Apache 2](https://img.shields.io/badge/License-Apache_2-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Lightweight OpenID Provider implemented in rust.

Aims to be: secure, fast, simple.

Currently supported features (WIP):

- [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)
- Authorization Code flow
- [OpenID Connect Session Management](https://openid.net/specs/openid-connect-session-1_0-10.html)

## Endpoints

- Openid Connect
  - https://openid.local:9000/.well-known/openid-configuration
  - https://openid.local:9000/oauth/authorize
  - https://openid.local:9000/oauth/token
  - https://openid.local:9000/oauth/userinfo
- Logout - based on OIDC Session management
  - https://openid.local:9000/oauth/end_session

How to run locally (for development): [development.md](https://github.com/bpteodor/flipid/blob/master/development.md).

## instalation & configuration

TODO
