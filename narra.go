// Package narra implements service logic.
package narra

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/LeKovr/go-kit/slogger"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"golang.org/x/oauth2"
	"gopkg.in/gorilla/securecookie.v1"
	cache "zgo.at/zcache/v2"
)

// codebeat:disable[TOO_MANY_IVARS]

// Config holds package options and constants.
type Config struct {
	MyURL       string `description:"Own host URL (autodetect if empty)" long:"my_url"`
	CallBackURL string `default:"/login"                                 description:"URL for Auth server's redirect" long:"cb_url"`

	Do401     bool   `description:"Do not redirect with http.StatusUnauthorized, process it" env:"DO401"                                                                  long:"do401"`
	Host      string `default:"http://gitea:8080"                                            description:"Authorization Server host"                                      env:"HOST"        long:"host"`
	Team      string `default:"dcape"                                                        description:"Authorization Server team which members has access to resource" env:"TEAM"        long:"team"`
	ClientID  string `description:"Authorization Server Client ID"                           env:"CLIENT_ID"                                                              long:"client_id"`
	ClientKey string `description:"Authorization Server Client key"                          env:"CLIENT_KEY"                                                             long:"client_key"`

	CacheExpire   time.Duration `default:"5m"  description:"Cache expire interval"  long:"cache_expire"`
	CacheCleanup  time.Duration `default:"10m" description:"Cache cleanup interval" long:"cache_cleanup"`
	ClientTimeout time.Duration `default:"10s" description:"HTTP Client timeout"    long:"client_timeout"`

	AuthHeader     string `default:"X-narra-token"                              description:"Use token from this header if given" long:"auth_header"`
	CookieDomain   string `description:"Auth cookie domain"                     long:"cookie_domain"`
	CookieName     string `default:"narra_token"                                description:"Auth cookie name"                    long:"cookie_name"`
	CookieSignKey  string `description:"Cookie sign key (32 or 64 bytes)"       env:"COOKIE_SIGN_KEY"                             long:"cookie_sign"`
	CookieCryptKey string `description:"Cookie crypt key (16, 24, or 32 bytes)" env:"COOKIE_CRYPT_KEY"                            long:"cookie_crypt"`

	UserHeader string `default:"X-Username" description:"HTTP Response Header for username" env:"USER_HEADER" long:"user_header"`

	BasicRealm     string `default:"narra"   description:"Basic Auth realm"                    long:"basic_realm"`
	BasicUser      string `default:"token"   description:"Basic Auth user name"                long:"basic_username"`
	BasicUserAgent string `default:"docker/" description:"UserAgent which requires Basic Auth" long:"basic_useragent"`

	Endpoint EndpointConfig `env-namespace:"EP" group:"Endpoint Options" namespace:"ep"`
}

// EndpointConfig holds Authorization Server Endpoint properties.
type EndpointConfig struct {
	Auth     string `default:"/login/oauth/authorize"    description:"Auth URI"                                long:"auth"`
	Token    string `default:"/login/oauth/access_token" description:"Token URI"                               long:"token"`
	User     string `default:"/api/v1/user"              description:"User info URI"                           long:"user"`
	Teams    string `default:"/api/v1/user/orgs"         description:"User teams URI"                          long:"teams"`
	TeamName string `default:"username"                  description:"Teams response field name for team name" long:"team_name"`
}

// codebeat:enable[TOO_MANY_IVARS]

// Service holds service attributes.
type Service struct {
	Config *Config
	api    *oauth2.Config
	cookie *securecookie.SecureCookie
	cache  *cache.Cache[string, string]
	//	provider      *ProviderConfig
	lock          sync.Mutex
	lockableMyURL string
}

var (
	// ErrNoTeam holds error: User is not in required team.
	ErrNoTeam = errors.New("user is not in required team")
	// ErrAuthNotGranted holds error: Auth not granted.
	ErrAuthNotGranted = errors.New("auth not granted")
	// ErrStateUnknown holds error: Unknown state.
	ErrStateUnknown = errors.New("unknown state")
	// ErrBasicTokenExpected holds error when username <> token.
	ErrBasicTokenExpected = errors.New("basic Auth username does not match")
	// ErrBasicAuthRequired holds 401 for docker client.
	ErrBasicAuthRequired = errors.New("basic Auth is required")
)

// Functional options
// https://github.com/tmrts/go-patterns/blob/master/idiom/functional-options.md

// Option is a functional options return type.
type Option func(*Service)

// Cache allows to change default cache lib.
func Cache(c *cache.Cache[string, string]) Option {
	return func(srv *Service) {
		srv.cache = c
	}
}

// Cookie allows to change default cookie lib.
func Cookie(cookie *securecookie.SecureCookie) Option {
	return func(srv *Service) {
		srv.cookie = cookie
	}
}

// New creates service.
func New(cfg *Config, options ...Option) *Service {
	srv := &Service{
		Config: cfg,
	}
	for _, option := range options {
		option(srv)
	}

	if srv.cookie == nil {
		srv.cookie = securecookie.New([]byte(cfg.CookieSignKey), []byte(cfg.CookieCryptKey))
	}

	if srv.cache == nil {
		srv.cache = cache.New[string, string](cfg.CacheExpire, cfg.CacheCleanup)
	}
	// some users asked to autoremove
	srv.Config.Host = strings.TrimSuffix(srv.Config.Host, "/")
	srv.api = &oauth2.Config{
		ClientID:     srv.Config.ClientID,
		ClientSecret: srv.Config.ClientKey,
		Scopes:       []string{srv.Config.BasicRealm},
		Endpoint: oauth2.Endpoint{
			TokenURL: srv.Config.Host + srv.Config.Endpoint.Token,
			AuthURL:  srv.Config.Host + srv.Config.Endpoint.Auth,
		},
	}

	if srv.Config.MyURL != "" {
		// given in config
		srv.api.RedirectURL = srv.Config.MyURL + srv.Config.CallBackURL
		// disable autodetect
		srv.lockableMyURL = srv.Config.MyURL
	}

	return srv
}

// IsMyURLEmpty check if app URL autodetect requested.
func (srv *Service) IsMyURLEmpty() bool {
	srv.lock.Lock()
	defer srv.lock.Unlock()

	return srv.lockableMyURL == ""
}

// SetMyURL changes app URL.
func (srv *Service) SetMyURL(scheme, host string) {
	// Use mutex here
	srv.lock.Lock()
	srv.lockableMyURL = fmt.Sprintf("%s://%s", scheme, host)
	srv.api.RedirectURL = srv.lockableMyURL + srv.Config.CallBackURL
	srv.lock.Unlock()
}

// AuthIsOK returns true if request is allowed to proceed.
func (srv *Service) AuthIsOK(w http.ResponseWriter, r *http.Request, replaceHeaders bool) bool {
	// Use the custom HTTP client when requesting a token.
	var ids *[]string

	var auth string

	ctx := r.Context()
	log := slogger.FromContext(ctx)

	scheme := "http"
	if r.TLS != nil {
		scheme += "s"
	}

	if srv.IsMyURLEmpty() {
		srv.SetMyURL(scheme, r.Host)
	}

	if u, p, ok := r.BasicAuth(); ok {
		log.Info("Basic Auth requested", "user", u)

		if u != srv.Config.BasicUser {
			warn(w, log, ErrBasicTokenExpected, srv.Config.BasicUser, http.StatusUnauthorized)

			return false
		}

		auth = p
	} else {
		auth = r.Header.Get(srv.Config.AuthHeader)
	}

	if auth != "" {
		// server token
		httpClient := &http.Client{Timeout: srv.Config.ClientTimeout}
		ctx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)
		client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: auth,
			TokenType:   "Bearer",
		}))

		var err error

		ids, err = srv.getMeta(ctx, client)
		if err != nil {
			warn(w, log, fmt.Errorf("get meta by header (%v) error: %w", r.Header, err), "", http.StatusUnauthorized)

			return false
		}

		log.Info("User meta", "tags", ids)
	} else {
		// No header => check others
		// Basic auth
		ua := r.Header.Get("User-Agent")
		if strings.HasPrefix(ua, srv.Config.BasicUserAgent) {
			log.Info("This ua requires Basic Auth", "ua", ua)
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", srv.Config.BasicRealm))
			http.Error(w, ErrBasicAuthRequired.Error(), http.StatusUnauthorized)

			return false
		}

		// Own cookie
		cookie, err := r.Cookie(srv.Config.CookieName)
		errMsg := "Cookie read error"

		if err == nil {
			err = srv.cookie.Decode(srv.Config.CookieName, cookie.Value, &ids)
			errMsg = "Cookie decode error"
		}

		if err != nil {
			if !errors.Is(err, http.ErrNoCookie) {
				log.Info(errMsg, "error", err.Error())
			}

			if replaceHeaders {
				r.Header.Set("X-Forwarded-Proto", scheme)
				r.Header.Set("X-Forwarded-Host", r.Host)
				r.Header.Set("X-Forwarded-Uri", r.RequestURI)
			}

			if srv.Config.Do401 && r.Header.Get("Accept") != "application/json" {
				// traefik wants redirect to provider
				srv.Stage1Handler().ServeHTTP(w, r)
			} else {
				// nginx and js wants 401
				http.Error(w, err.Error(), http.StatusUnauthorized)
			}

			return false
		}
	}

	if srv.Config.Team == "" || slices.Contains(*ids, srv.Config.Team) {
		log.Info("User authorized", "user", (*ids)[0])
		r.Header.Add(srv.Config.UserHeader, (*ids)[0])

		return true
	}

	warn(w, log, fmt.Errorf("user %s Team %s: %w", (*ids)[0], srv.Config.Team, ErrNoTeam), "", http.StatusForbidden)

	return false
}

// HTTP handler pattern, see
// https://www.alexedwards.net/blog/a-recap-of-request-handling

// AuthHandler is a Nginx auth_request handler.
func (srv *Service) AuthHandler() http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if srv.AuthIsOK(w, r, false) {
			w.WriteHeader(http.StatusOK)
		}
	}

	return http.HandlerFunc(fn)
}

// Stage1Handler handles 401 error & redirects user to auth server.
func (srv *Service) Stage1Handler() http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		log := slogger.FromContext(r.Context())

		uuid, err := uuid.NewRandom()
		if err != nil {
			warn(w, log, err, "UUID Generate error", http.StatusServiceUnavailable)

			return
		}

		url := fmt.Sprintf("%s://%s%s",
			r.Header.Get("X-Forwarded-Proto"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Forwarded-Uri"),
		)
		log.Debug("Got UUID", "uuid", uuid.String(), "url", url)
		srv.cache.Set(uuid.String(), url)
		redirect := srv.api.AuthCodeURL(uuid.String(), oauth2.AccessTypeOffline)

		log.Debug("Redirect", "url", redirect)
		w.Header().Add("Content-Type", "application/json")
		http.Redirect(w, r, redirect, http.StatusFound)
	}

	return http.HandlerFunc(fn)
}

// Stage2Handler fetches token & user info.
func (srv *Service) Stage2Handler() http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		log := slogger.FromContext(r.Context())

		url, ids, err := srv.processMeta(r)
		if err != nil {
			warn(w, log, err, "Meta processing failed", http.StatusServiceUnavailable)

			return
		}

		log.Debug("Got Meta", "ids", ids)
		// store ids in cookie
		if encoded, err := srv.cookie.Encode(srv.Config.CookieName, &ids); err == nil {
			cookie := &http.Cookie{
				Name:  srv.Config.CookieName,
				Value: encoded,
				Path:  "/",
			}
			if srv.Config.CookieDomain != "" {
				cookie.Domain = srv.Config.CookieDomain
			}

			http.SetCookie(w, cookie)
			log.Debug("All OK, set cookie", "domain", srv.Config.CookieDomain, "redirect", url)
			http.Redirect(w, r, url, http.StatusFound)
		} else {
			warn(w, log, err, "Cookie encode error", http.StatusServiceUnavailable)
		}
	}

	return http.HandlerFunc(fn)
}

// LogoutHandler handles auth cookie clearing.
func (srv *Service) LogoutHandler() http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		cookie := &http.Cookie{
			Name:    srv.Config.CookieName,
			Value:   "",
			Path:    "/",
			Expires: time.Unix(0, 0),
		}
		if srv.Config.CookieDomain != "" {
			cookie.Domain = srv.Config.CookieDomain
		}

		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/", http.StatusFound)
	}

	return http.HandlerFunc(fn)
}

// SetupRoutes attaches OAuth2 URIs.
func (srv *Service) SetupRoutes(mux *http.ServeMux, privPrefix string) {
	mux.Handle("/auth", srv.AuthHandler())
	mux.Handle(srv.Config.CallBackURL, srv.Stage2Handler())
	// Just clear app cookie (real logout processed in gitea)
	mux.Handle(privPrefix+"logout", srv.LogoutHandler())
	// we don't use handler for status 401
	if !srv.Config.Do401 {
		mux.Handle("/401/", srv.Stage1Handler())
	}
}

// ProtectMiddleware requires auth for given URLs mask.
func (srv *Service) ProtectMiddleware(next http.Handler, re *regexp.Regexp) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log := slogger.FromContext(r.Context())
		if re.MatchString(r.URL.Path) {
			log.Debug("URL is protected", "url", r.URL.Path)

			if !srv.AuthIsOK(w, r, true) {
				return
			}

			w.Header().Set("Last-Modified", "")
		}

		next.ServeHTTP(w, r)
	})
}

// request processes requests to Auth service.
func (srv *Service) request(ctx context.Context, client *http.Client, url string, data interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.Config.Host+url, http.NoBody)
	if err != nil {
		return fmt.Errorf("request create error: %w", err)
	}

	req.Header.Add("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request error: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("not OK with request, status: %d", resp.StatusCode)
	}

	defer func() {
		err = resp.Body.Close()
		if err != nil {
			log := slogger.FromContext(ctx)
			log.Warn("body close", "err", err)
		}
	}()

	err = jsoniter.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return fmt.Errorf("parse response error: %w", err)
	}

	return nil
}

// getMeta fetches user metadata from auth server.
func (srv *Service) getMeta(ctx context.Context, client *http.Client) (*[]string, error) {
	// get username
	var user map[string]interface{}

	err := srv.request(ctx, client, srv.Config.Endpoint.User, &user)
	if err != nil {
		return nil, fmt.Errorf("get user metadata: %w", err)
	}

	name, ok := user["username"].(string)
	if !ok {
		return nil, fmt.Errorf("cannot cast name as string: (%v)", user["username"])
	}

	tags := []string{name}

	if srv.Config.Team == "" {
		// no team check
		return &tags, nil
	}
	// get user teams
	url := srv.Config.Endpoint.Teams
	if strings.Contains(url, "%s") {
		// mattermost wants user id in URL
		url = fmt.Sprintf(url, user["id"])
	}

	var orgs []map[string]interface{}

	err = srv.request(ctx, client, url, &orgs)
	if err != nil {
		return nil, fmt.Errorf("get team metadata: %w", err)
	}

	for _, o := range orgs {
		team, ok := o[srv.Config.Endpoint.TeamName].(string)
		if !ok {
			log := slogger.FromContext(ctx)
			log.Warn("cannot cast team name", "name", o[srv.Config.Endpoint.TeamName])
		} else {
			tags = append(tags, team)
		}
	}

	return &tags, nil
}

// processMeta fetches user's metadata at auth stage 2.
func (srv *Service) processMeta(r *http.Request) (string, *[]string, error) {
	ctx := r.Context()
	log := slogger.FromContext(ctx)
	code := r.FormValue("code")
	state := r.FormValue("state")
	// ?? r.FormValue("error")
	// error=invalid_request&error_description
	log.Debug("Auth data", "code", code, "state", state)

	if code == "" || state == "" {
		return "", nil, ErrAuthNotGranted
	}

	url, found := srv.cache.Get(state)
	if !found {
		return "", nil, ErrStateUnknown
	}

	srv.cache.Delete(state)

	// Use the custom HTTP client when requesting a token.
	httpClient := &http.Client{Timeout: srv.Config.ClientTimeout}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	tok, err := srv.api.Exchange(ctx, code)
	if err != nil {
		return "", nil, fmt.Errorf("token fetch failed: %w", err)
	}

	log.Debug("API token", "token", tok)
	client := srv.api.Client(ctx, tok)

	// load usernames from provider
	ids, err := srv.getMeta(ctx, client)
	log.Debug("User meta", "tags", ids)

	return url, ids, err
}

// warn prints warning to log and http.
func warn(w http.ResponseWriter, log *slog.Logger, e error, msg string, status int) {
	log.Error(msg, "err", e)
	http.Error(w, e.Error(), status)
}
