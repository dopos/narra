package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jessevdk/go-flags"
	"github.com/patrickmn/go-cache"
	"github.com/zenazn/goji/graceful"
	"gopkg.in/gorilla/securecookie.v1"
)

// Config holds program options
type Config struct {
	Listen   string `long:"listen" default:":8080" description:"Addr and port which server listens at"`
	Host     string `long:"host" default:"http://narra.dev.lan" description:"Own host URL"`
	LoginURL string `long:"login_url" default:"/login" description:"Auth redirect URL"`

	ASType      string `long:"as_type" env:"AS_TYPE" default:"gitea"  choice:"gitea" choice:"mmost" description:"Authorization Server type (gitea|mmost)"`
	ASHost      string `long:"as_host" env:"AS_HOST" default:"http://gitea:8080" description:"Authorization Server host"`
	ASTeam      string `long:"as_team" env:"AS_TEAM" default:"dcape" description:"Authorization Server team which members has access to resource"`
	ASClientID  string `long:"as_client_id" env:"AS_CLIENT_ID" description:"Authorization Server Client ID"`
	ASClientKey string `long:"as_client_key" env:"AS_CLIENT_KEY" description:"Authorization Server Client key"`

	AuthHeader     string `long:"auth_header" default:"X-narra-token" description:"Use token from this header if given"`
	CookieDomain   string `long:"cookie_domain"  description:"Auth cookie domain"`
	CookieName     string `long:"cookie_name" default:"narra_token" description:"Auth cookie name"`
	CookieSignKey  string `long:"cookie_sign" env:"COOKIE_SIGN_KEY" description:"Cookie sign key (32 or 64 bytes)"`
	CookieCryptKey string `long:"cookie_crypt" env:"COOKIE_CRYPT_KEY" description:"Cookie crypt key (16, 24, or 32 bytes)"`
}

// Provider holds Authorization Server properties
type Provider struct {
	Auth        string
	Token       string
	User        string
	Team        string
	TokenPrefix string
	TeamName    string
}

var (
	// Providers holds supported Authorization Servers data
	Providers = map[string]Provider{
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

// getToken fetches user token from auth server
func getToken(w http.ResponseWriter, cfg *Config, code string) string {
	// Mattermost does not support "application/json" so use form
	data := url.Values{
		"client_id":     []string{cfg.ASClientID},
		"client_secret": []string{cfg.ASClientKey},
		"code":          []string{code},
		"grant_type":    []string{"authorization_code"},
		"redirect_uri":  []string{cfg.Host + cfg.LoginURL},
	}
	resp, err := http.Post(cfg.ASHost+Providers[cfg.ASType].Token, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))

	if err != nil {
		log.Printf("get token error: %s", err.Error())
		http.Error(w, "Error loading user data", http.StatusInternalServerError)
		return ""
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("Req token error: %+v", resp)
		w.WriteHeader(resp.StatusCode)
		return ""
	}

	defer resp.Body.Close()
	log.Printf("Resp: %+v", resp)
	var meta map[string]string
	json.NewDecoder(resp.Body).Decode(&meta)
	if meta["access_token"] == "" {
		http.Error(w, "No token", http.StatusInternalServerError)
		return ""
	}
	return meta["access_token"]
}

// getMeta fetches user metadata from auth server
func getMeta(w http.ResponseWriter, cfg *Config, token string) (tags []string) {
	client := &http.Client{}

	// get username
	req, err := http.NewRequest("GET", cfg.ASHost+Providers[cfg.ASType].User, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Accept", "application/json")

	req.Header.Add("Authorization", Providers[cfg.ASType].TokenPrefix+token)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Gitea req error: %s", err.Error())
		http.Error(w, "Error loading user data", http.StatusInternalServerError)
		return
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("Req error: %+v", resp)
		w.WriteHeader(resp.StatusCode)
		return
	}
	defer resp.Body.Close()

	var user map[string]string
	json.NewDecoder(resp.Body).Decode(&user)
	log.Printf("User: %+v", user)
	tags = append(tags, user["username"])

	if len(cfg.ASTeam) == 0 {
		return
	}
	// get user groups
	url := Providers[cfg.ASType].Team
	if strings.Contains(url, "%s") {
		url = fmt.Sprintf(url, user["id"])
	}
	req, err = http.NewRequest("GET", cfg.ASHost+url, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", Providers[cfg.ASType].TokenPrefix+token)
	resp, err = client.Do(req)
	if err != nil {
		log.Printf("Error loading org data: %v", err)
		return
	}
	defer resp.Body.Close()

	var orgs []map[string]string
	json.NewDecoder(resp.Body).Decode(&orgs)
	log.Printf("Resp: %+v", orgs)
	for _, o := range orgs {
		log.Printf("Org: %+v", o)
		tags = append(tags, o[Providers[cfg.ASType].TeamName])
	}

	return
}

// InitHandler handles 401 error & redirects user to auth server
func InitHandler(w http.ResponseWriter, r *http.Request) {

	cfg := r.Context().Value("Config").(*Config)
	c := r.Context().Value("Cache").(*cache.Cache)

	uuid, err := uuid.NewRandom()
	if err != nil {
		log.Fatal("Gen error:", err)
	}
	url := r.Header.Get("X-Original-Uri")
	log.Printf("UUID: %s REQ:%+v\n", uuid.String(), url)

	c.Set(uuid.String(), url, cache.DefaultExpiration)
	req, err := http.NewRequest("GET", cfg.ASHost+Providers[cfg.ASType].Auth, nil)
	if err != nil {
		log.Fatal(err)
	}

	q := req.URL.Query()
	q.Add("client_id", cfg.ASClientID)
	q.Add("redirect_uri", cfg.Host+cfg.LoginURL)
	q.Add("response_type", "code")
	q.Add("state", uuid.String())
	req.URL.RawQuery = q.Encode()

	log.Printf("Redir to %s", req.URL.String())
	http.Redirect(w, r, req.URL.String(), http.StatusFound)
}

// PostHandler handles redirect from auth provider
// fetches token & user info
func PostHandler(w http.ResponseWriter, r *http.Request) {
	/*	if r.Method != "POST" {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}
	*/code := r.FormValue("code")
	state := r.FormValue("state")
	log.Printf("** Auth data (%s:%s)", code, state)
	if code == "" || state == "" {
		http.Error(w, "auth not granted", http.StatusForbidden)
		return
	}
	// Get data from context
	cfg := r.Context().Value("Config").(*Config)
	sc := r.Context().Value("Cookie").(*securecookie.SecureCookie)
	c := r.Context().Value("Cache").(*cache.Cache)

	url, found := c.Get(state)
	if !found {
		http.Error(w, "Unknown state "+state, http.StatusMethodNotAllowed)
		return
	}

	token := getToken(w, cfg, code)

	// load usernames from gitea
	ids := getMeta(w, cfg, token)
	if len(ids) == 0 {
		return
	}
	log.Printf("Meta IDs: %v", ids)
	// store usernames in cookie
	if encoded, err := sc.Encode(cfg.CookieName, &ids); err == nil {
		cookie := &http.Cookie{
			Name:  cfg.CookieName,
			Value: encoded,
			Path:  "/",
		}

		if cfg.CookieDomain != "" {
			cookie.Domain = cfg.CookieDomain
		}
		http.SetCookie(w, cookie)
		log.Printf("All OK, redir to %s", url)
		http.Redirect(w, r, url.(string), http.StatusFound)
	} else {
		log.Println("Cookie encode error", err)
	}
}

// fetchToken fetches token from header or cookie
func fetchToken(r *http.Request, cfg *Config) string {
	if auth := r.Header.Get(cfg.AuthHeader); auth != "" {
		return auth
	}
	if cookie, err := r.Cookie(cfg.CookieName); err == nil {
		return cookie.Value
	}
	return ""
}

// AuthHandler is a Nginx auth_request handler
func AuthHandler(w http.ResponseWriter, r *http.Request) {

	// Get data from context
	cfg := r.Context().Value("Config").(*Config)
	sc := r.Context().Value("Cookie").(*securecookie.SecureCookie)

	token := fetchToken(r, cfg)
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	//log.Printf("Token: %v", token)

	ids := []string{}
	if err := sc.Decode(cfg.CookieName, token, &ids); err == nil {
		if stringExists(ids, cfg.ASTeam) {
			w.Header().Add("X-Username", ids[0])
			w.WriteHeader(http.StatusOK)
		} else {
			http.Error(w, fmt.Sprintf("user %s is not in required org %s", ids[0], cfg.ASTeam), http.StatusForbidden)
		}
		return
	} else {
		log.Println("Cookie encode error", err)
	}
	http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
}

// AddContext add context vars to request
func AddContext(cfg *Config, sc *securecookie.SecureCookie, c *cache.Cache, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.Method, "-", r.RequestURI)
		ctx0 := context.WithValue(r.Context(), "Config", cfg)
		ctx1 := context.WithValue(ctx0, "Cache", c)
		ctx := context.WithValue(ctx1, "Cookie", sc)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func main() {

	// Parse options
	var cfg Config
	_, err := flags.Parse(&cfg)
	if err != nil {
		if e, ok := err.(*flags.Error); ok && e.Type == flags.ErrHelp {
			os.Exit(1) // help printed
		} else {
			log.Printf("Config error: %v", e)
			os.Exit(2) // error message written already
		}
	}

	log.Printf("NARRA v%s. Nginx Auth Request via Remote API", Version)
	log.Println("Copyright (C) 2017, Alexey Kovrizhkin <lekovr+dopos@gmail.com>")

	// http://stackoverflow.com/questions/18106749/golang-catch-signals
	signalChannel := make(chan os.Signal, 2)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-signalChannel
		log.Printf("Got signal %v", sig)
		os.Exit(0)
	}()

	var signKey = []byte(cfg.CookieSignKey)
	var cryptKey = []byte(cfg.CookieCryptKey)
	var sc = securecookie.New(signKey, cryptKey)

	var c = cache.New(5*time.Minute, 10*time.Minute)

	log.Printf("Start listening at %s", cfg.Listen)

	mux := http.NewServeMux()
	mux.Handle(cfg.LoginURL, AddContext(&cfg, sc, c, http.HandlerFunc(PostHandler)))
	mux.Handle("/auth", AddContext(&cfg, sc, c, http.HandlerFunc(AuthHandler)))
	mux.Handle("/", AddContext(&cfg, sc, c, http.HandlerFunc(InitHandler)))
	log.Fatal(graceful.ListenAndServe(cfg.Listen, mux))

}

// -----------------------------------------------------------------------------

func checkErr(w http.ResponseWriter, err error, note string) {
	if err != nil {
		if w != nil {
			status := http.StatusInternalServerError
			http.Error(w, http.StatusText(status), status)
		}
		log.Fatalf("%s: %s", note, err)
	}
}

// -----------------------------------------------------------------------------

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
