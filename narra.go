package narra

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gopkg.in/birkirb/loggers.v1"

	"github.com/google/uuid"
	"github.com/patrickmn/go-cache"
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

type Service struct {
	log      loggers.Contextual
	Config   Config
	cookie   *securecookie.SecureCookie
	cache    *cache.Cache
	provider *ProviderConfig
}

type Option func(*Service)

func Cache(cache *cache.Cache) Option {
	return func(srv *Service) {
		srv.cache = cache
	}
}
func Cookie(cookie *securecookie.SecureCookie) Option {
	return func(srv *Service) {
		srv.cookie = cookie
	}
}
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
func fetchToken(r *http.Request, cfg Config) string {
	if auth := r.Header.Get(cfg.AuthHeader); auth != "" {
		return auth
	}
	if cookie, err := r.Cookie(cfg.CookieName); err == nil {
		return cookie.Value
	}
	return ""
}

func (srv *Service) AuthHandler() http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {

		token := fetchToken(r, srv.Config)
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		srv.log.Debugf("Headers: %v", r.Header)
		//log.Printf("Token: %v", token)

		ids := []string{}
		if err := srv.cookie.Decode(srv.Config.CookieName, token, &ids); err != nil {
			srv.log.Error("Cookie encode error", err)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		if stringExists(ids, srv.Config.Team) {
			w.Header().Add("X-Username", ids[0])
			w.WriteHeader(http.StatusOK)
		} else {
			http.Error(w, fmt.Sprintf("user %s is not in required team %s", ids[0], srv.Config.Team), http.StatusForbidden)
		}

	}
	return http.HandlerFunc(fn)
}

func (srv *Service) Stage1Handler() http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {

		uuid, err := uuid.NewRandom()
		if err != nil {
			srv.log.Fatal("Gen error:", err)
		}
		url := r.Header.Get("X-Original-Uri")
		srv.log.Printf("UUID: %s REQ:%+v\n", uuid.String(), url)

		srv.cache.Set(uuid.String(), url, cache.DefaultExpiration)
		req, err := http.NewRequest("GET", srv.Config.Host+srv.provider.Auth, nil)
		if err != nil {
			srv.log.Fatal(err)
		}

		q := req.URL.Query()
		q.Add("client_id", srv.Config.ClientID)
		q.Add("redirect_uri", srv.Config.MyURL+srv.Config.CallBackURL)
		q.Add("response_type", "code")
		q.Add("state", uuid.String())
		req.URL.RawQuery = q.Encode()

		srv.log.Printf("Redir to %s", req.URL.String())
		http.Redirect(w, r, req.URL.String(), http.StatusFound)
	}
	return http.HandlerFunc(fn)
}

// getToken fetches user token from auth server
func (srv *Service) getToken(w http.ResponseWriter, code string) string {
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
		//	log.Printf("get token error: %s", err.Error())
		http.Error(w, "Error loading user data", http.StatusInternalServerError)
		return ""
	}
	if resp.StatusCode != http.StatusOK {
		//	log.Printf("Req token error: %+v", resp)
		w.WriteHeader(resp.StatusCode)
		return ""
	}

	defer resp.Body.Close()
	//log.Printf("Resp: %+v", resp)
	var meta map[string]string
	json.NewDecoder(resp.Body).Decode(&meta)
	if meta["access_token"] == "" {
		http.Error(w, "No token", http.StatusInternalServerError)
		return ""
	}
	return meta["access_token"]
}

// getMeta fetches user metadata from auth server
func (srv *Service) getMeta(w http.ResponseWriter, token string) *[]string {
	client := &http.Client{}

	// get username
	req, err := http.NewRequest("GET", srv.Config.Host+srv.provider.User, nil)
	if err != nil {
		srv.log.Fatal(err)
	}
	req.Header.Add("Accept", "application/json")

	req.Header.Add("Authorization", srv.provider.TokenPrefix+token)
	resp, err := client.Do(req)
	if err != nil {
		srv.log.Printf("Gitea req error: %s", err.Error())
		http.Error(w, "Error loading user data", http.StatusInternalServerError)
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		srv.log.Printf("Req error: %+v", resp)
		w.WriteHeader(resp.StatusCode)
		return nil
	}
	defer resp.Body.Close()

	var user map[string]string
	json.NewDecoder(resp.Body).Decode(&user)
	srv.log.Printf("User: %+v", user)
	tags := []string{user["username"]}

	if len(srv.Config.Team) == 0 {
		return nil
	}
	// get user groups
	url := srv.provider.Team
	if strings.Contains(url, "%s") {
		url = fmt.Sprintf(url, user["id"])
	}
	req, err = http.NewRequest("GET", srv.Config.Host+url, nil)
	if err != nil {
		srv.log.Fatal(err)
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", srv.provider.TokenPrefix+token)
	resp, err = client.Do(req)
	if err != nil {
		srv.log.Printf("Error loading org data: %v", err)
		return nil
	}
	defer resp.Body.Close()

	var orgs []map[string]string
	json.NewDecoder(resp.Body).Decode(&orgs)
	srv.log.Printf("Resp: %+v", orgs)
	for _, o := range orgs {
		srv.log.Printf("Org: %+v", o)
		tags = append(tags, o[srv.provider.TeamName])
	}

	return &tags
}

// Stage2Handler handles redirect from auth provider
// fetches token & user info
func (srv *Service) Stage2Handler() http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		code := r.FormValue("code")
		state := r.FormValue("state")
		srv.log.Debugf("** Auth data (%s:%s)", code, state)
		if code == "" || state == "" {
			http.Error(w, "auth not granted", http.StatusForbidden)
			return
		}
		url, found := srv.cache.Get(state)
		if !found {
			http.Error(w, "Unknown state "+state, http.StatusMethodNotAllowed)
			return
		}
		srv.cache.Delete(state)

		token := srv.getToken(w, code)

		// load usernames from gitea
		ids := srv.getMeta(w, token)
		if len(*ids) == 0 {
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
			srv.log.Debugf("Cookie encode error", err)
		}
	}
	return http.HandlerFunc(fn)
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
