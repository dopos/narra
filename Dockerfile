# FROM golang:1.15.5-alpine3.12
FROM ghcr.io/dopos/golang-alpine:v1.16.10-alpine3.14.3

ENV NARRA_VERSION 0.23.2
RUN apk add --no-cache git curl

WORKDIR /opt/narra
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-X main.version=`git describe --tags --always`" -a ./cmd/narra

FROM scratch

MAINTAINER Alexey Kovrizhkin <lekovr+dopos@gmail.com>

LABEL org.opencontainers.image.title="narra"
LABEL org.opencontainers.image.description="Nginx Auth_Request (and traefik forwardauth) via Remote Api"
LABEL org.opencontainers.image.authors="Alexey Kovrizhkin <lekovr+dopos@gmail.com>"
LABEL org.opencontainers.image.url="https://github.com/dopos/narra"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /
COPY --from=0 /opt/narra/narra .
# Need for SSL
COPY --from=0 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8080
ENTRYPOINT ["/narra"]

