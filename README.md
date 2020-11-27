# narra

nginx auth_request via remote api

Project status: MVP

This program intended to be used for client authentication with
* [nginx http auth_request module](https://nginx.ru/en/docs/http/ngx_http_auth_request_module.html)
* [traefik ForwardAuth](https://doc.traefik.io/traefik/middlewares/forwardauth/)

OAuth2 services supported:

* [gitea](https://gitea.io)
* [mattermost](https://mattermost.com/)

Also, narra accepts auth via header with Gitea Access Tokens for non-interactive use cases.

Usage example available inside [dcape](https://github.com/dopos/dcape) project (see apps/cis there).

## Install

narra is available as docker image, see https://store.docker.com/community/images/dopos/narra

## Use

Chain of requests with warning `Cookie decode error: securecookie: the value is not valid ` in logfile means you have the same cookie for upper domain. 
This is configuration problem and you should rename one of these cookies (see `--as.cookie_name`).

## See also

* https://redbyte.eu/en/blog/using-the-nginx-auth-request-module/
* https://github.com/tlex/traefik-oauth2-proxy

### OAuth2 proxies

* https://github.com/thomseddon/traefik-forward-auth (cannot be used while [this PR open](https://github.com/thomseddon/traefik-forward-auth/pull/159))
* https://github.com/oauth2-proxy/oauth2-proxy (waiting for [this](https://github.com/oauth2-proxy/oauth2-proxy/issues/874) and probably more)
* for nginx: https://github.com/vouch/vouch-proxy (waiting for [this](https://github.com/vouch/vouch-proxy/issues/180))
* https://github.com/buzzfeed/sso
* https://github.com/pomerium/pomerium
* https://github.com/travisghansen/external-auth-server

## History

Primary goal is to allow logins via [gitea](https://gitea.io) API, starting from v0.10 we support OAuth2 services like [gitea](https://gitea.io) or [mattermost](https://mattermost.com/).

Since v0.20 narra can act as Traefik2 ForwardAuth service.

## License

The MIT License (MIT), see [LICENSE](LICENSE).

Copyright (c) 2017-2020 Aleksei Kovrizhkin <lekovr+dopos@gmail.com>
