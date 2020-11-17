# narra
nginx auth_request via remote api

This program intended to be used with [nginx http auth_request module](https://nginx.ru/en/docs/http/ngx_http_auth_request_module.html) for users authentication.

Primary goal is to allow logins via [gitea](https://gitea.io) API, starting from v0.10 we support OAuth2 services like [gitea](https://gitea.io) or [mattermost](https://mattermost.com/).

Since v0.20 this app can act as Traefik2 ForwardAuth service.

Usage example available inside [dcape](https://github.com/dopos/dcape) project (see apps/cis there).

## Install

narra is available as docker image, see https://store.docker.com/community/images/dopos/narra

## See also

* https://redbyte.eu/en/blog/using-the-nginx-auth-request-module/
* https://github.com/tlex/traefik-oauth2-proxy

### OAuth2 proxies

* https://github.com/thomseddon/traefik-forward-auth (cannot be used while [This PR open](https://github.com/thomseddon/traefik-forward-auth/pull/159))
* https://github.com/oauth2-proxy/oauth2-proxy (waiting for [This](https://github.com/oauth2-proxy/oauth2-proxy/issues/874) and probably more)

## License

The MIT License (MIT), see [LICENSE](LICENSE).

Copyright (c) 2017-2020 Aleksei Kovrizhkin <lekovr+dopos@gmail.com>
