# build container
FROM rust:1.41 as builder
#RUN apt-get update && apt-get install -y libssl-dev libsqlite3-dev
WORKDIR /src
COPY . .
RUN cargo build --release


# run container
#FROM alpine
#FROM ubuntu
FROM debian:buster-slim
LABEL maintainer="teo@bran.tech"

#RUN apk update && apk upgrade && apk add --no-cache openssl sqlite
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y openssl sqlite3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /src/target/release/flipid ./
COPY --from=builder /src/static static/
COPY --from=builder /src/templates templates/

#USER 1000
EXPOSE 9000

CMD "./flipid"
