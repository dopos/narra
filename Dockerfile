ARG GOLANG_IMAGE=ghcr.io/dopos/golang-alpine
ARG GOLANG_VERSION=v1.19.7-alpine3.17.2
ARG APP=narra

FROM --platform=$BUILDPLATFORM ${GOLANG_IMAGE}:${GOLANG_VERSION} as build

ARG APP

COPY . /src/$APP
WORKDIR /src/$APP

ARG GOPROXY TARGETOS TARGETARCH
RUN --mount=type=cache,id=gobuild,target=/root/.cache/go-build \
    --mount=type=cache,id=gomod,target=/go/pkg \
    make build-standalone

FROM scratch

LABEL \
  org.opencontainers.image.title="narra" \
  org.opencontainers.image.description="Nginx Auth_Request (and traefik forwardauth) via Remote API" \
  org.opencontainers.image.authors="lekovr+dopos@gmail.com" \
  org.opencontainers.image.licenses="MIT"

WORKDIR /

ARG APP

COPY --from=build /src/$APP/$APP /app

# Need for SSL
COPY --from=0 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8080
ENTRYPOINT [ "/app" ]
