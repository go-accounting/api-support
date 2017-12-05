package apisupport

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	oidc "github.com/coreos/go-oidc"
	"github.com/go-accounting/config"
)

type Api struct {
	cfg      config.Config
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

type Decoder func(v interface{}) error

func New(path string) (*Api, error) {
	a := &Api{}
	var err error
	a.cfg, err = config.New(path)
	if err != nil {
		return nil, err
	}
	a.provider, err = oidc.NewProvider(context.Background(), a.cfg["OpenId/Provider"].(string))
	if err != nil {
		return nil, err
	}
	a.verifier = a.provider.Verifier(&oidc.Config{ClientID: a.cfg["OpenId/ClientId"].(string)})
	return a, nil
}

func (a *Api) Run(w http.ResponseWriter, f func() (interface{}, error)) {
	v, err := f()
	if check(err, w) {
		return
	}
	if v != nil {
		w.Header().Set("Content-Type", "application/json")
		check(json.NewEncoder(w).Encode(v), w)
	}
}

func (a *Api) Config() config.Config {
	return a.cfg
}

func (a *Api) UserFromRequest(w http.ResponseWriter, r *http.Request) string {
	var token string
	tokens, ok := r.Header["Authorization"]
	if ok && len(tokens) >= 1 {
		token = tokens[0]
		token = strings.TrimPrefix(token, "Bearer ")
	}
	idtoken, err := a.verifier.Verify(r.Context(), token)
	if check(err, w) {
		return ""
	}
	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	if err := idtoken.Claims(&claims); check(err, w) {
		return ""
	}
	if claims.Email == "" {
		check(fmt.Errorf("empty email"), w)
		return ""
	}
	if !claims.Verified {
		check(fmt.Errorf("email not verified"), w)
		return ""
	}
	return claims.Email
}

func (a *Api) Encode(w http.ResponseWriter, v interface{}, err error) {
	if check(err, w) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	check(json.NewEncoder(w).Encode(v), w)
}

func (a *Api) Decode(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func check(err error, w http.ResponseWriter) bool {
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	return err != nil
}
