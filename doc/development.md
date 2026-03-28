# Development info

Some random stuff usefull for development.

## Configuration

### 1. Cryptographic material
```sh
cd config

# generate RSA keys for the JWT (RS256 alg)
openssl genrsa -out rsa.key 4096

# generate eliptic courve keys
openssl ecparam -name prime256v1 -genkey -noout -out es256.key
openssl pkcs8 -topk8 -nocrypt -in es256.key -out es256.pkcs8.key # workaround: convert to PKCS8 (https://github.com/Keats/jsonwebtoken?tab=readme-ov-file#convert-sec1-private-key-to-pkcs8)

openssl ecparam -name secp384r1 -genkey -noout -out es384.key
openssl pkcs8 -topk8 -nocrypt -in es384.key -out es384.pkcs8.key

openssl ecparam -name secp521r1 -genkey -noout -out es512.key
openssl pkcs8 -topk8 -nocrypt -in es512.key -out es512.pkcs8.key

# Generate Ed25519 keys (EdDSA)
openssl genpkey -algorithm ed25519 -out ed25519.key
openssl pkcs8 -topk8 -nocrypt -in ed25519.key -out ed25519.pkcs8.key

# Generate ECDSA keys (ES256K) NOT SUPPORTED
#openssl ecparam -name secp256k1 -genkey -noout -out ec-secp256k1.key
#openssl pkcs8 -topk8 -nocrypt -in ec-secp256k1.key -out ec-secp256k1.pkcs8.key

# (optional) generate TLS cert + key for the server
openssl req -x509 -newkey rsa:4096 -keyout tls.key -out tls.cert -nodes
```

### DB

- install dependencies: `sudo apt install libsqlite3-dev`
- install diesel cli: `cargo install diesel_cli --no-default-features --features sqlite`
- create test db (sqlite): `diesel migration run`

## Build

- with cargo: `cargo build`
  - build a release with `cargo build -r`
- with docker: `docker run --rm -ti -v $(pwd):/work -v $HOME/.cargo/:/usr/local/cargo -w /work rust cargo build`

## build container & run

- build container image: `docker build . -t my-flipid`
  - build a release with: `docker build . -t my-flipid --build-arg PROFILE=release`
- run locally: `docker run -ti -p 9000:9000   -v ${pwd}:/app   -e "RUN_BEHIND_PROXY=true" -w /app  my-flipid` or

```bash
docker run --rm -ti -p 9000:9000 --name flip-id \
  -v $(pwd)/target/demo.db:/app/target/demo.db \
  -v $(pwd)/.env:/app/.env:ro \
  -v $(pwd)/config:/app/config:ro \
  -w /app \
  -e "RUN_BEHIND_PROXY=true" \
  my-flipid
```

## demo app

```bash
cd doc
docker compose up
open http://localhost:9009
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
