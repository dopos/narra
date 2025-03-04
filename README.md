# narra

nginx auth_request via remote api

Project status: Production use since [2017](https://github.com/dopos/dcape/commit/394c24830e38b2c88098efc772939883b1a13b0f).

This program intended to be used for client authentication with

* [nginx http auth_request module](https://nginx.ru/en/docs/http/ngx_http_auth_request_module.html)
* [traefik ForwardAuth](https://doc.traefik.io/traefik/middlewares/forwardauth/)

OAuth2 services supported:

* [gitea](https://gitea.io)

Also, narra accepts auth via header with Gitea Access Tokens for non-interactive use cases, see [dcape-config-cli](https://github.com/dopos/dcape-config-cli).

Usage example available inside [dcape](https://github.com/dopos/dcape) project.

## Install

narra is available as docker image at

* [GitHub container registry](https://github.com/orgs/dopos/packages/container/package/narra)

## Configuration

See [config.md](config.md)

## Changes

See [CHANGELOG.md](CHANGELOG.md)

## Статистика исходного кода

## Problems known

Chain of requests with warning `Cookie decode error: securecookie: the value is not valid` in logfile means you have the same cookie for upper domain.
This is configuration problem and you should rename one of these cookies (see `--as.cookie_name`).

## See also

* [using-the-nginx-auth-request-module](https://redbyte.eu/en/blog/using-the-nginx-auth-request-module/)
* [traefik-oauth2-proxy](https://github.com/tlex/traefik-oauth2-proxy)

### OAuth2 proxies

* [traefik-forward-auth](https://github.com/thomseddon/traefik-forward-auth) (cannot be used while [this PR open](https://github.com/thomseddon/traefik-forward-auth/pull/159))
* [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy) (waiting for [this](https://github.com/oauth2-proxy/oauth2-proxy/issues/874) and probably more)
* for nginx: [vouch-proxy](https://github.com/vouch/vouch-proxy) (waiting for [this](https://github.com/vouch/vouch-proxy/issues/180))
* [buzzfeed/sso](https://github.com/buzzfeed/sso)
* [pomerium](https://github.com/pomerium/pomerium)
* [external-auth-server](https://github.com/travisghansen/external-auth-server)

## History

Primary goal was to allow logins via [gitea](https://gitea.io) API. Starting from v0.10 narra uses OAuth2 services like [gitea](https://gitea.io) or [mattermost](https://mattermost.com/).

Since v0.20 narra can act as Traefik2 ForwardAuth service.

## License

The MIT License (MIT), see [LICENSE](LICENSE).

Copyright (c) 2017-2025 Aleksei Kovrizhkin <lekovr+dopos@gmail.com>
