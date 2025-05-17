package main

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"io/ioutil"
	"mime"
	"net/http"
	"strings"
)

func getLogoutUrl(ctx context.Context, issuer string) (string, error) {
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return "", err
	}
	resp, err := doRequest(ctx, req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", resp.Status, body)
	}

	var p providerJSON
	err = unmarshalResp(resp, body, &p)
	if err != nil {
		return "", fmt.Errorf("oidc: failed to decode provider discovery object: %v", err)
	}
	if p.FrontChannelLogoutSessionSupported || p.FrontChannelLogoutSupported {
		return p.LogoutUrl, nil
	}
	return "", nil
}

type providerJSON struct {
	Issuer      string   `json:"issuer"`
	AuthURL     string   `json:"authorization_endpoint"`
	TokenURL    string   `json:"token_endpoint"`
	JWKSURL     string   `json:"jwks_uri"`
	UserInfoURL string   `json:"userinfo_endpoint"`
	Algorithms  []string `json:"id_token_signing_alg_values_supported"`

	BackChannelLogoutSupported         bool `json:"backchannel_logout_supported"`
	BackChannelLogoutSessionSupported  bool `json:"backchannel_logout_session_supported"`
	FrontChannelLogoutSupported        bool `json:"frontchannel_logout_supported"`
	FrontChannelLogoutSessionSupported bool `json:"frontchannel_logout_session_supported"`

	LogoutUrl string `json:"end_session_endpoint"`
}

func doRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	client := http.DefaultClient
	if c := getClient(ctx); c != nil {
		client = c
	}
	return client.Do(req.WithContext(ctx))
}

func unmarshalResp(r *http.Response, body []byte, v interface{}) error {
	err := json.Unmarshal(body, &v)
	if err == nil {
		return nil
	}
	ct := r.Header.Get("Content-Type")
	mediaType, _, parseErr := mime.ParseMediaType(ct)
	if parseErr == nil && mediaType == "application/json" {
		return fmt.Errorf("got Content-Type = application/json, but could not unmarshal as JSON: %v", err)
	}
	return fmt.Errorf("expected Content-Type = application/json, got %q: %v", ct, err)
}

func getClient(ctx context.Context) *http.Client {
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		return c
	}
	return nil
}
