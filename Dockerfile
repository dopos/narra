FROM golang:1.15.5-alpine3.12

MAINTAINER Alexey Kovrizhkin <lekovr+dopos@gmail.com>

ENV NARRA_VERSION 0.21
RUN apk add --no-cache git curl

WORKDIR /opt/narra
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-X main.version=`git describe --tags --always`" -a ./cmd/narra

FROM scratch

WORKDIR /
COPY --from=0 /opt/narra/narra .
# Need for SSL
COPY --from=0 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8080
ENTRYPOINT ["/narra"]

