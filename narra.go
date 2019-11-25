package narra

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/patrickmn/go-cache"
	"gopkg.in/birkirb/loggers.v1"
	"gopkg.in/gorilla/securecookie.v1"
)

// Config holds program options
type Config struct {
	MyURL       string `long:"my_url" default:"http://narra.dev.lan" description:"Own host URL"`
	CallBackURL string `long:"cb_url" default:"/login" description:"URL for Auth server's redirect"`

	Type      string `long:"type" env:"TYPE" default:"gitea"  choice:"gitea" choice:"mmost" description:"Authorization Server type (gitea|mmost)"`
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
	return srv
}

// fetchToken fetches token from header or cookie
func fetchToken(r *http.Request, header string, cookie string) string {
	if auth := r.Header.Get(header); auth != "" {
		return auth
	}
	if cookie, err := r.Cookie(cookie); err == nil {
		return cookie.Value
	}
	return ""
}

// HTTP handler pattern, see
// https://www.alexedwards.net/blog/a-recap-of-request-handling

// AuthHandler is a Nginx auth_request handler
func (srv *Service) AuthHandler() http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		token := fetchToken(r, srv.Config.AuthHeader, srv.Config.CookieName)
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		srv.log.Debugf("Headers: %v", r.Header)
		ids := []string{}
		if err := srv.cookie.Decode(srv.Config.CookieName, token, &ids); err != nil {
			srv.log.Error("Cookie encode error", err)
			http.Error(w, "Cookie encode error", http.StatusInternalServerError)
			return
		}
		if stringExists(ids, srv.Config.Team) {
			srv.log.Debugf("User %s authorized", ids[0])
			w.Header().Add("X-Username", ids[0])
			w.WriteHeader(http.StatusOK)
		} else {
			http.Error(w, fmt.Sprintf("user %s is not in required team %s", ids[0], srv.Config.Team), http.StatusForbidden)
		}
	}
	return http.HandlerFunc(fn)
}

// Stage1Handler handles 401 error & redirects user to auth server
func (srv *Service) Stage1Handler() http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		uuid, err := uuid.NewRandom()
		if err != nil {
			srv.log.Fatal("Gen error:", err)
		}
		url := r.Header.Get("X-Original-Uri")
		srv.log.Debugf("UUID: %s URI:%+v\n", uuid.String(), url)
		srv.cache.Set(uuid.String(), url, cache.DefaultExpiration)
		req, err := http.NewRequest("GET", srv.Config.Host+srv.provider.Auth, nil)
		if err != nil {
			srv.log.Errorf("Request create error: %v", err)
			http.Error(w, "Request create error", http.StatusInternalServerError)
			return
		}
		q := req.URL.Query()
		q.Add("client_id", srv.Config.ClientID)
		q.Add("redirect_uri", srv.Config.MyURL+srv.Config.CallBackURL)
		q.Add("response_type", "code")
		q.Add("state", uuid.String())
		req.URL.RawQuery = q.Encode()

		srv.log.Debugf("Redir to %s", req.URL.String())
		http.Redirect(w, r, req.URL.String(), http.StatusFound)
	}
	return http.HandlerFunc(fn)
}

// Stage2Handler handles redirect from auth provider
// fetches token & user info
func (srv *Service) Stage2Handler() http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		code := r.FormValue("code")
		state := r.FormValue("state")
		// TODO: r.FormValue("error")
		srv.log.Debugf("Auth data: (%s:%s)", code, state)
		if code == "" || state == "" {
			http.Error(w, "auth not granted", http.StatusExpectationFailed)
			return
		}
		url, found := srv.cache.Get(state)
		if !found {
			srv.log.Warnf("Unknown state: %s", state)
			http.Error(w, "Unknown state", http.StatusNotAcceptable)
			return
		}
		srv.cache.Delete(state)
		token, err := srv.getToken(w, code)
		if err != nil {
			srv.log.Warnf("Token error: %w", err)
			http.Error(w, "Token error", http.StatusNotAcceptable)
			return
		}
		// load usernames from gitea
		ids, err := srv.getMeta(w, *token)
		if err != nil {
			srv.log.Warnf("Meta error: %w", err)
			http.Error(w, "Meta error", http.StatusNotAcceptable)
			return
		}
		if len(*ids) == 0 {
			srv.log.Warnf("User ID list is empty")
			http.Error(w, "User ID list is empty", http.StatusNotAcceptable)
			return
		}
		srv.log.Debugf("Meta IDs: %v", ids)
		// store usernames in cookie
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
			srv.log.Warnf("Cookie encode error: %w", err)
			http.Error(w, "Cookie encode error", http.StatusNotAcceptable)
		}
	}
	return http.HandlerFunc(fn)
}

// getToken fetches user token from auth server
func (srv *Service) getToken(w http.ResponseWriter, code string) (*string, error) {
	// Mattermost does not support "application/json" so use form
	data := url.Values{
		"client_id":     []string{srv.Config.ClientID},
		"client_secret": []string{srv.Config.ClientKey},
		"code":          []string{code},
		"grant_type":    []string{"authorization_code"},
		"redirect_uri":  []string{srv.Config.MyURL + srv.Config.CallBackURL},
	}
	resp, err := http.Post(srv.Config.Host+srv.provider.Token, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("POST create error: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Not OK with POST token request, status: %d", resp.StatusCode)
	}
	defer resp.Body.Close()
	var meta map[string]string
	json.NewDecoder(resp.Body).Decode(&meta)
	token := meta["access_token"]
	if token == "" {
		return nil, fmt.Errorf("No token in AS responce")
	}
	return &token, nil
}

// getMeta fetches user metadata from auth server
func (srv *Service) getMeta(w http.ResponseWriter, token string) (*[]string, error) {
	client := &http.Client{}
	// get username
	req, err := http.NewRequest("GET", srv.Config.Host+srv.provider.User, nil)
	if err != nil {
		return nil, fmt.Errorf("GET user request create error: %w", err)
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", srv.provider.TokenPrefix+token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET user request error: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Not OK with POST user request, status: %d", resp.StatusCode)
	}
	defer resp.Body.Close()
	var user map[string]string
	json.NewDecoder(resp.Body).Decode(&user)
	srv.log.Debugf("User: %+v", user)
	tags := []string{user["username"]}

	if len(srv.Config.Team) == 0 {
		// no team check
		return &tags, nil
	}
	// get user groups
	url := srv.provider.Team
	if strings.Contains(url, "%s") {
		// mattermost wants user id in URL
		url = fmt.Sprintf(url, user["id"])
	}
	req, err = http.NewRequest("GET", srv.Config.Host+url, nil)
	if err != nil {
		return nil, fmt.Errorf("GET team request create error: %w", err)
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", srv.provider.TokenPrefix+token)
	resp, err = client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET team request error: %w", err)
	}
	defer resp.Body.Close()
	var orgs []map[string]string
	err = json.NewDecoder(resp.Body).Decode(&orgs)
	srv.log.Printf("Resp: %+v", orgs)
	for _, o := range orgs {
		tags = append(tags, o[srv.provider.TeamName])
	}
	return &tags, nil
}

// Check if str exists in strings slice
func stringExists(strings []string, str string) bool {
	if len(strings) > 0 {
		for _, s := range strings {
			if str == s {
				return true
			}
		}
	}
	return false
}
