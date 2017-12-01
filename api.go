package apisupport

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"plugin"
	"strings"

	oidc "github.com/coreos/go-oidc"
	yaml "gopkg.in/yaml.v2"
)

type Api struct {
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	err      error
}

func NewApi() *Api {
	return &Api{}
}

func (a *Api) Error() error {
	return a.err
}

func (a *Api) SetClientCredentials(provider, clientId string) error {
	if a.err != nil {
		return a.err
	}
	a.provider, a.err = oidc.NewProvider(context.Background(), provider)
	if a.err == nil {
		a.verifier = a.provider.Verifier(&oidc.Config{ClientID: clientId})
	}
	return a.err
}

func (a *Api) UnmarshalSettings(path string, v interface{}) error {
	if a.err != nil {
		return a.err
	}
	var data []byte
	data, a.err = ioutil.ReadFile(path)
	if a.err != nil {
		return a.err
	}
	a.err = yaml.Unmarshal(data, v)
	return a.err
}

func (a *Api) UserFromRequest(r *http.Request) (string, error) {
	if a.err != nil {
		return "", a.err
	}
	var token string
	tokens, ok := r.Header["Authorization"]
	if ok && len(tokens) >= 1 {
		token = tokens[0]
		token = strings.TrimPrefix(token, "Bearer ")
	}
	idtoken, err := a.verifier.Verify(r.Context(), token)
	if err != nil {
		return "", err
	}
	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	if err := idtoken.Claims(&claims); err != nil {
		return "", err
	}
	if !claims.Verified {
		return "", fmt.Errorf("email not verified")
	}
	return claims.Email, nil
}

func (_ *Api) LoadSymbol(pluginFile, symbolName string) (interface{}, error) {
	p, err := plugin.Open(pluginFile)
	if err != nil {
		return nil, err
	}
	return p.Lookup(symbolName)
}

func (_ *Api) Check(err error, w http.ResponseWriter) bool {
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	return err != nil
}
