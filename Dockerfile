
#FROM alpine:3
FROM ubuntu:24.04

LABEL maintainer="bpteodor@gmail.com"

ARG PROFILE=debug

#RUN apk update && apk upgrade && apk add --no-cache openssl sqlite
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y openssl sqlite3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY target/${PROFILE}/flipid ./
COPY static/ static/
COPY templates templates/

#USER 1000
EXPOSE 9000

CMD [ "/app/flipid" ]
