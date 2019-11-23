FROM golang:1.13.4-alpine3.10

MAINTAINER Alexey Kovrizhkin <lekovr+dopos@gmail.com>

ENV        NARRA_VERSION 0.1

WORKDIR /opt/narra
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -o narra

FROM scratch

WORKDIR /
COPY --from=0 /opt/narra/narra .
# Need for SSL
COPY --from=0 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8080
ENTRYPOINT ["/narra"]

