
FROM debian:buster-slim
LABEL maintainer="teos@bran.tech"

ARG PROFILE=debug

#RUN apk update && apk upgrade && apk add --no-cache openssl sqlite
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y openssl sqlite3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY target/$PROFILE/flipid ./
COPY static/ static/
COPY templates templates/

#USER 1000
EXPOSE 9000

CMD "./flipid"
