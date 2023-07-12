# Docker image versions
ARG go_ver=v1.18.6-alpine3.16.2

# Docker images
ARG go_img=ghcr.io/dopos/golang-alpine

FROM ${go_img}:${go_ver}

ENV NARRA_VERSION 0.24.1
RUN apk add --no-cache git curl

WORKDIR /build
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-X main.version=`git describe --tags --always` -X main.repo=`git config --get remote.origin.url`" -a ./cmd/narra

FROM scratch

MAINTAINER Alexey Kovrizhkin <lekovr+dopos@gmail.com>

LABEL \
  org.opencontainers.image.title="narra" \
  org.opencontainers.image.description="Nginx Auth_Request (and traefik forwardauth) via Remote Api" \
  org.opencontainers.image.authors="Alexey Kovrizhkin <lekovr+dopos@gmail.com>" \
  org.opencontainers.image.url="https://github.com/dopos/narra" \
  org.opencontainers.image.licenses="MIT"

WORKDIR /
COPY --from=0 /build/narra .
# Need for SSL
COPY --from=0 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8080
ENTRYPOINT ["/narra"]

