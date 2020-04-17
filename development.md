# Development info

Some random stuff usefull for development.

## Configuration

- generate cert + key for the server
`openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -nodes`
- generate RSA keys for the RS256 alg
  - `ssh-keygen -t rsa -b 4096 -C "your_email@example.com" -f ./id_rsa`
  - `ssh-keygen -p -m PEM -f id_rsa`
  - `openssl rsa -in id_rsa -outform pem > id_rsa.pem`

## DB

- install dependencies: `sudo apt install libsqlite3-dev`
- install diesel cli: `cargo install diesel_cli --no-default-features --features sqlite`
- create test db (sqlite): `diesel migration run`

## pack & test

- build with docker: `docker build . -t bpteodor/my_openid_provider`
- run locally:

```bash
docker run --rm -ti -p 9000:9000 \
  -v $(pwd)/target/test.db:/app/target/test.db \
  -v $(pwd)/.env:/app/.env \
  -v $(pwd)/config:/app/config \
  -e "RUN_BEHIND_PROXY=true" \
  bpteodor/my_openid_provider
```

## Links

### OIDC & JWT

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html)
- [JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [JSON Web Algorithms (JWA)](https://tools.ietf.org/html/rfc7518)

### actix-web

- [docs](https://actix.rs/docs/)
- [API](https://github.com/actix/examples)
- [API actix_files](https://docs.rs/actix-files/0.2.1/actix_files/)

### diesel

- [guides](https://diesel.rs/guides/getting-started/)
- [API](http://docs.diesel.rs/diesel/index.html)
- [examples](https://github.com/actix/examples/tree/master/diesel/)
