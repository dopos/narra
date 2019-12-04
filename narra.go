package narra

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/json-iterator/go"
	"github.com/patrickmn/go-cache"
	"golang.org/x/oauth2"
	"gopkg.in/birkirb/loggers.v1"
	"gopkg.in/gorilla/securecookie.v1"
)

// Config holds program options
type Config struct {
	MyURL       string `long:"my_url" default:"http://narra.dev.lan" description:"Own host URL"`
	CallBackURL string `long:"cb_url" default:"/login" description:"URL for Auth server's redirect"`

	//nolint:staticcheck // Multiple struct tag "choice" is allowed
	Type string `long:"type" env:"TYPE" default:"gitea"  choice:"gitea" choice:"mmost" description:"Authorization Server type (gitea|mmost)"`

	Host      string `long:"host" env:"HOST" default:"http://gitea:8080" description:"Authorization Server host"`
	Team      string `long:"team" env:"TEAM" default:"dcape" description:"Authorization Server team which members has access to resource"`
	ClientID  string `long:"client_id" env:"CLIENT_ID" description:"Authorization Server Client ID"`
	ClientKey string `long:"client_key" env:"CLIENT_KEY" description:"Authorization Server Client key"`

	AuthHeader     string `long:"auth_header" default:"X-narra-token" description:"Use token from this header if given"`
	CookieDomain   string `long:"cookie_domain"  description:"Auth cookie domain"`
	CookieName     string `long:"cookie_name" default:"narra_token" description:"Auth cookie name"`
	CookieSignKey  string `long:"cookie_sign" env:"COOKIE_SIGN_KEY" description:"Cookie sign key (32 or 64 bytes)"`
	CookieCryptKey string `long:"cookie_crypt" env:"COOKIE_CRYPT_KEY" description:"Cookie crypt key (16, 24, or 32 bytes)"`
}

// ProviderConfig holds Authorization Server properties
type ProviderConfig struct {
	Auth        string
	Token       string
	User        string
	Team        string
	TokenPrefix string
	TeamName    string
}

// Service holds service attributes
type Service struct {
	Config   Config
	log      loggers.Contextual
	api      *oauth2.Config
	cookie   *securecookie.SecureCookie
	cache    *cache.Cache
	provider *ProviderConfig
}

//Functional options
//https://github.com/tmrts/go-patterns/blob/master/idiom/functional-options.md

// Option is a functional options return type
type Option func(*Service)

// Cache allows to change default cache lib
func Cache(cache *cache.Cache) Option {
	return func(srv *Service) {
		srv.cache = cache
	}
}

// Cookie allows to change default cookie lib
func Cookie(cookie *securecookie.SecureCookie) Option {
	return func(srv *Service) {
		srv.cookie = cookie
	}
}

// Provider allows to change authorization server config
func Provider(prov *ProviderConfig) Option {
	return func(srv *Service) {
		srv.provider = prov
	}
}

var (
	// Providers holds supported Authorization Servers properties
	Providers = map[string]*ProviderConfig{
		"gitea": {
			Auth:        "/login/oauth/authorize",
			Token:       "/login/oauth/access_token",
			User:        "/api/v1/user",
			Team:        "/api/v1/user/orgs",
			TokenPrefix: "token ",
			TeamName:    "username",
		},
		"mmost": {
			Auth:        "/oauth/authorize",
			Token:       "/oauth/access_token",
			User:        "/api/v4/users/me",
			Team:        "/api/v4/users/%s/teams",
			TokenPrefix: "Bearer ",
			TeamName:    "name",
		},
	}
)

// New creates service
func New(cfg Config, log loggers.Contextual, options ...Option) *Service {
	srv := &Service{
		Config: cfg,
		log:    log,
	}
	for _, option := range options {
		option(srv)
	}
	if srv.cookie == nil {
		srv.cookie = securecookie.New([]byte(cfg.CookieSignKey), []byte(cfg.CookieCryptKey))
	}
	if srv.cache == nil {
		srv.cache = cache.New(5*time.Minute, 10*time.Minute)
	}
	if srv.provider == nil {
		srv.provider = Providers[cfg.Type]
	}
	srv.api = &oauth2.Config{
		ClientID:     srv.Config.ClientID,
		ClientSecret: srv.Config.ClientKey,
		//Scopes:       []string{"SCOPE1", "SCOPE2"},
		RedirectURL: srv.Config.MyURL + srv.Config.CallBackURL,
		Endpoint: oauth2.Endpoint{
			TokenURL: srv.Config.Host + srv.provider.Token,
			AuthURL:  srv.Config.Host + srv.provider.Auth,
		},
	}
	return srv
}

// HTTP handler pattern, see
// https://www.alexedwards.net/blog/a-recap-of-request-handling

// AuthHandler is a Nginx auth_request handler
func (srv *Service) AuthHandler() http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		// Use the custom HTTP client when requesting a token.
		var ids *[]string
		var err error
		if auth := r.Header.Get(srv.Config.AuthHeader); auth != "" {
			// server token
			httpClient := &http.Client{Timeout: 2 * time.Second}
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)
			client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: auth,
				TokenType:   "Bearer",
			}))
			ids, err = srv.getMeta(client)
			if err != nil {
				srv.log.Warnf("Get meta by header: %v", r.Header)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		} else {
			// own cookie
			cookie, err := r.Cookie(srv.Config.CookieName)
			if err != nil {
				srv.error(w, http.StatusUnauthorized, fmt.Errorf("Cookie decode error: %w", err))
				return
			}
			if err := srv.cookie.Decode(srv.Config.CookieName, cookie.Value, &ids); err != nil {
				srv.log.Error("Cookie decode error", err)
				http.Error(w, "Cookie decode error", http.StatusUnauthorized)
				return
			}
		}
		if len(srv.Config.Team) == 0 || stringExists(ids, srv.Config.Team) {
			srv.log.Debugf("User %s authorized", (*ids)[0])
			w.Header().Add("X-Username", (*ids)[0])
			w.WriteHeader(http.StatusOK)
		} else {
			http.Error(w, fmt.Sprintf("user %s is not in required team %s", (*ids)[0], srv.Config.Team), http.StatusForbidden)
		}
	}
	return http.HandlerFunc(fn)
}

func (srv *Service) error(w http.ResponseWriter, status int, e error) {
	srv.log.Warn(e)
	http.Error(w, e.Error(), status)
}

// Stage1Handler handles 401 error & redirects user to auth server
func (srv *Service) Stage1Handler() http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		uuid, err := uuid.NewRandom()
		if err != nil {
			srv.log.Error("UUID Generate error: ", err)
			http.Error(w, "UUID Generate error", http.StatusServiceUnavailable)
			return
		}
		url := r.Header.Get("X-Original-Uri")
		srv.log.Debugf("UUID: %s URI:%+v\n", uuid.String(), url)
		srv.cache.Set(uuid.String(), url, cache.DefaultExpiration)
		redirect := srv.api.AuthCodeURL(uuid.String(), oauth2.AccessTypeOffline)
		srv.log.Debugf("Redir to %s", redirect)
		http.Redirect(w, r, redirect, http.StatusFound)
	}
	return http.HandlerFunc(fn)
}

// Stage2Handler handles redirect from auth provider,
// fetches token & user info
func (srv *Service) Stage2Handler() http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		code := r.FormValue("code")
		state := r.FormValue("state")
		// TODO: r.FormValue("error")
		// error=invalid_request&error_description
		srv.log.Debugf("Auth data: (%s:%s)", code, state)
		if code == "" || state == "" {
			http.Error(w, "Auth not granted", http.StatusServiceUnavailable)
			return
		}
		url, found := srv.cache.Get(state)
		if !found {
			http.Error(w, "Unknown state", http.StatusServiceUnavailable)
			return
		}
		srv.cache.Delete(state)

		// Use the custom HTTP client when requesting a token.
		httpClient := &http.Client{Timeout: 2 * time.Second}
		ctx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)

		tok, err := srv.api.Exchange(ctx, code)
		if err != nil {
			srv.log.Warn(fmt.Errorf("Token fetch failed: %w", err))
			http.Error(w, "Token fetch failed", http.StatusServiceUnavailable)
			return
		}

		client := srv.api.Client(ctx, tok)

		// load usernames from provider
		ids, err := srv.getMeta(client)
		if err != nil {
			srv.log.Warnf("Meta fetch failed: %v", err)
			http.Error(w, "Meta fetch failed", http.StatusServiceUnavailable)
			return
		}

		srv.log.Debugf("Meta IDs: %v", ids)
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
			srv.log.Debugf("All OK, redir to %s", url)
			http.Redirect(w, r, url.(string), http.StatusFound)
		} else {
			srv.log.Warnf("Cookie encode error: %v", err)
			http.Error(w, "Cookie encode error", http.StatusServiceUnavailable)
		}
	}
	return http.HandlerFunc(fn)
}

func (srv *Service) request(client *http.Client, url string, data interface{}) error {
	req, err := http.NewRequest("GET", srv.Config.Host+url, nil)
	if err != nil {
		return fmt.Errorf("Request create error: %w", err)
	}
	req.Header.Add("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Request error: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Not OK with request, status: %d", resp.StatusCode)
	}
	defer resp.Body.Close()
	err = jsoniter.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return fmt.Errorf("Parse response error: %w", err)
	}
	return nil
}

// getMeta fetches user metadata from auth server
func (srv *Service) getMeta(client *http.Client) (*[]string, error) {
	// get username
	var user map[string]interface{}
	err := srv.request(client, srv.provider.User, &user)
	if err != nil {
		return nil, fmt.Errorf("Get user metadata: %w", err)
	}
	srv.log.Debugf("User: %+v", user)
	tags := []string{user["username"].(string)}

	if len(srv.Config.Team) == 0 {
		// no team check
		return &tags, nil
	}
	// get user teams
	url := srv.provider.Team
	if strings.Contains(url, "%s") {
		// mattermost wants user id in URL
		url = fmt.Sprintf(url, user["id"])
	}

	var orgs []map[string]interface{}
	err = srv.request(client, url, &orgs)
	if err != nil {
		return nil, fmt.Errorf("Get team metadata: %w", err)
	}

	for _, o := range orgs {
		tags = append(tags, o[srv.provider.TeamName].(string))
	}
	srv.log.Debugf("Tags: %+v", tags)
	return &tags, nil
}

// Check if str exists in strings slice
func stringExists(strings *[]string, str string) bool {
	if len(*strings) > 0 {
		for _, s := range *strings {
			if str == s {
				return true
			}
		}
	}
	return false
}
