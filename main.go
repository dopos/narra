//go:generate go-bindata -pkg $GOPACKAGE -prefix html -o bindata.go html/

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/elazarl/go-bindata-assetfs"
	"github.com/jessevdk/go-flags"
	"github.com/zenazn/goji/graceful"
	"gopkg.in/gorilla/securecookie.v1"
)

/* ------------------------------------------------------------------------------------------- */
// Config holds program options
type Config struct {
	Listen string `long:"listen" default:":8080" description:"Addr and port which server listens at"`

	Providers []string `long:"provider"   default:"gitea"             description:"Allowed auth provider type(s)"`
	GiteaHost string   `long:"gitea_host" default:"http://gitea:8080" description:"Gitea host"`
	GiteaOrg  string   `long:"gitea_org"  default:"dcape1709"         description:"Gitea org which members are allowed to login"`
	//	GiteaOrg  []string `long:"gitea_org"  default:"dcape1709"         description:"Gitea org which members are allowed to login"`

	CookieDomain   string `long:"cookie_domain"  description:"Auth cookie domain"`
	CookieName     string `long:"cookie_name" default:"narra_token" description:"Auth cookie name"`
	CookieExpire   int    `long:"cookie_expire" default:"14" description:"Cookie TTL (days)"`
	CookieSignKey  string `long:"cookie_sign" description:"Cookie sign key (32 or 64 bytes)"`
	CookieCryptKey string `long:"cookie_crypt" description:"Cookie crypt key (16, 24, or 32)"`
}

// Note: Change gitea_org to logout all users

type accounts []account
type account struct {
	Username string `json:"username"`
	Fullname string `json:"full_name"`
	Message  string `json:"message"`
}

const (
	GiteaUserURL = "/api/v1/user"
	GiteaOrgURL  = "/api/v1/user/orgs"
)

// -----------------------------------------------------------------------------

func giteaIDs(w http.ResponseWriter, cfg *Config, name, password string) (tags []string) {
	auth := base64.StdEncoding.EncodeToString([]byte(name + ":" + password))
	client := &http.Client{}

	// get username
	req, err := http.NewRequest("GET", cfg.GiteaHost+GiteaUserURL, nil)
	req.Header.Add("Accept", "application/json")
	log.Printf("Sending auth: %s", auth)
	req.Header.Add("Authorization", "Basic "+auth)
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Error loading user data", http.StatusInternalServerError)
		return
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("Req error: %+v", resp)
		w.WriteHeader(resp.StatusCode)
		return
	}
	log.Printf("Resp: %+v", resp)
	var user account
	json.NewDecoder(resp.Body).Decode(&user)
	if user.Message != "" {
		http.Error(w, user.Message, http.StatusInternalServerError)
		return
	}
	log.Printf("User: %+v", user)
	tags = append(tags, user.Username)

	if len(cfg.GiteaOrg) > 0 {
		// get user groups
		req, err = http.NewRequest("GET", cfg.GiteaHost+GiteaOrgURL, nil)
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Authorization", "Basic "+auth)
		resp, err = client.Do(req)
		if err != nil {
			log.Printf("Error loading org data: %v", err)
			return
		}
		var orgs accounts
		json.NewDecoder(resp.Body).Decode(&orgs)
		for _, o := range orgs {
			log.Printf("Org: %+v", o)
			tags = append(tags, o.Username)
		}
	}
	return
}

// -----------------------------------------------------------------------------

// PostHandler converts post request body to string
func PostHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("1****** Request: %s - %s", r.Method, r.URL.Path)
	log.Printf("1** Headers: %+v", r.Header)
	if r.Method != "POST" {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	name := r.FormValue("name")
	password := r.FormValue("pass")
	keep := r.FormValue("keep")

	log.Printf("1** Auth data (%s:%s) (%s)", name, password, keep)

	// Get data from context
	cfg := r.Context().Value("Config").(*Config)
	sc := r.Context().Value("Cookie").(*securecookie.SecureCookie)

	// load usernames from gitea
	ids := giteaIDs(w, cfg, name, password)
	if len(ids) == 0 {
		return
	}

	// store usernames in cookie
	days := cfg.CookieExpire
	if keep == "" {
		days = 0
	}
	expiration := time.Now().Add(time.Duration(days) * 24 * time.Hour)
	if encoded, err := sc.Encode(cfg.CookieName, &ids); err == nil {
		cookie := &http.Cookie{
			Name:    cfg.CookieName,
			Value:   encoded,
			Path:    "/",
			Expires: expiration,
		}
		if cfg.CookieDomain != "" {
			cookie.Domain = cfg.CookieDomain
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
	} else {
		log.Println("Cookie encode error", err)
	}
}

// -----------------------------------------------------------------------------
func AuthHandler(w http.ResponseWriter, r *http.Request) {

	log.Printf("****** Request: %s - %s", r.Method, r.URL.Path)
	log.Printf("** Headers: %+v", r.Header)

	// Get data from context
	cfg := r.Context().Value("Config").(*Config)
	sc := r.Context().Value("Cookie").(*securecookie.SecureCookie)

	var cookie *http.Cookie
	var err error
	if cookie, err = r.Cookie(cfg.CookieName); err != nil {
		log.Printf("cookie fetch error: %v", err)
		log.Printf("status %s", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		//		http.Error(w, http.StatusText(401), 401)
		return
	}

	ids := []string{}
	if err := sc.Decode(cfg.CookieName, cookie.Value, &ids); err == nil {
		if stringExists(ids, cfg.GiteaOrg) {
			w.Header().Add("X-User", ids[0])
			w.WriteHeader(http.StatusOK)
			return
		} else {
			log.Println("user is not in required org")
		}
	} else {
		log.Println("Cookie encode error", err)
	}
	//	w.WriteHeader(http.StatusUnauthorized)
	http.Error(w, http.StatusText(401), 401)

}

// -----------------------------------------------------------------------------

func AddContext(cfg *Config, sc *securecookie.SecureCookie, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.Method, "-", r.RequestURI)
		ctx0 := context.WithValue(r.Context(), "Config", cfg)
		ctx := context.WithValue(ctx0, "Cookie", sc)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// -----------------------------------------------------------------------------

func main() {

	// Parse options
	var cfg Config
	_, err := flags.Parse(&cfg)
	if err != nil {
		if e, ok := err.(*flags.Error); ok && e.Type == flags.ErrHelp {
			os.Exit(1) // help printed
		} else {
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

	log.Printf("Start listening at %s", cfg.Listen)

	mux := http.NewServeMux()
	// mux.Handle("/", http.FileServer(assetFS()))
	//	mux.Handle("/", http.FileServer(&assetfs.AssetFS{Asset: Asset, AssetDir: AssetDir, AssetInfo: AssetInfo}))
	mux.Handle("/", AddContext(&cfg, sc, http.FileServer(&assetfs.AssetFS{Asset: Asset, AssetDir: AssetDir, AssetInfo: AssetInfo})))
	mux.Handle("/login", AddContext(&cfg, sc, http.HandlerFunc(PostHandler)))
	mux.Handle("/auth", AddContext(&cfg, sc, http.HandlerFunc(AuthHandler)))
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
