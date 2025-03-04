
### Main Options

| Name | ENV | Type | Default | Description |
|------|-----|------|---------|-------------|
| listen               | -                    | string | :8080 | Addr and port which server listens at |
| grace                | -                    | Duration | 1m | Stop grace period |
| fs.path              | -                    | string | - | Path to static files (default: don't serve static) |
| fs.protect           | -                    | string | - | Regexp for pages which require auth |
| version              | -                    | bool | false | Show version and exit |
| config_gen           | CONFIG_GEN           | ,json,md,mk | - | Generate and print config definition in given format and exit (default: '', means skip) |
| config_dump          | CONFIG_DUMP          | string | - | Dump config dest filename |

### Logging Options {#log}

| Name | ENV | Type | Default | Description |
|------|-----|------|---------|-------------|
| log.debug            | -                    | bool | false | Show debug info |
| log.dest             | -                    | string | - | Log destination (defailt: STDERR) |

### Auth Service Options {#as}

| Name | ENV | Type | Default | Description |
|------|-----|------|---------|-------------|
| as.my_url            | -                    | string | - | Own host URL (autodetect if empty) |
| as.cb_url            | -                    | string | /login | URL for Auth server's redirect |
| as.do401             | AS_DO401             | bool | false | Do not redirect with http.StatusUnauthorized, process it |
| as.host              | AS_HOST              | string | http://gitea:8080 | Authorization Server host |
| as.team              | AS_TEAM              | string | dcape | Authorization Server team which members has access to resource |
| as.client_id         | AS_CLIENT_ID         | string | - | Authorization Server Client ID |
| as.client_key        | AS_CLIENT_KEY        | string | - | Authorization Server Client key |
| as.cache_expire      | -                    | Duration | 5m | Cache expire interval |
| as.cache_cleanup     | -                    | Duration | 10m | Cache cleanup interval |
| as.client_timeout    | -                    | Duration | 10s | HTTP Client timeout |
| as.auth_header       | -                    | string | X-narra-token | Use token from this header if given |
| as.cookie_domain     | -                    | string | - | Auth cookie domain |
| as.cookie_name       | -                    | string | narra_token | Auth cookie name |
| as.cookie_sign       | AS_COOKIE_SIGN_KEY   | string | - | Cookie sign key (32 or 64 bytes) |
| as.cookie_crypt      | AS_COOKIE_CRYPT_KEY  | string | - | Cookie crypt key (16, 24, or 32 bytes) |
| as.user_header       | AS_USER_HEADER       | string | X-Username | HTTP Response Header for username |
| as.basic_realm       | -                    | string | narra | Basic Auth realm |
| as.basic_username    | -                    | string | token | Basic Auth user name |
| as.basic_useragent   | -                    | string | docker/ | UserAgent which requires Basic Auth |

### Endpoint Options {#as.ep}

| Name | ENV | Type | Default | Description |
|------|-----|------|---------|-------------|
| as.ep.auth           | -                    | string | /login/oauth/authorize | Auth URI |
| as.ep.token          | -                    | string | /login/oauth/access_token | Token URI |
| as.ep.user           | -                    | string | /api/v1/user | User info URI |
| as.ep.teams          | -                    | string | /api/v1/user/orgs | User teams URI |
| as.ep.team_name      | -                    | string | username | Teams response field name for team name |
| as.ep.token_prefix   | -                    | string | token  | Token header prefix |
