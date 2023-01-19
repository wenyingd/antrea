package auth

import (
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

const (
	authHeader = "Authorization"

	cfgClientID     = "client-id"
	cfgClientSecret = "client-secret"
	cfgOrgID        = "org-id"
)

func init() {
	if err := rest.RegisterAuthProviderPlugin("csp", newCSPAuthProvider); err != nil {
		klog.Fatalf("Failed to register CSP auth plugin: %v", err)
	}
}

type cspAuthProvider struct {
	clientID     string
	clientSecret string
	orgID        string
	tokenManager oauth2.TokenSource
}

func newCSPAuthProvider(_ string, cfg map[string]string, _ rest.AuthProviderConfigPersister) (rest.AuthProvider, error) {
	return &cspAuthProvider{
		clientID:     cfg[cfgClientID],
		clientSecret: cfg[cfgClientSecret],
		orgID:        cfg[cfgOrgID],
	}, nil
}

func (p *cspAuthProvider) WrapTransport(rt http.RoundTripper) http.RoundTripper {
	return &cspRoundTripper{
		tokenSource:  p.tokenManager,
		roundTripper: rt,
	}
}

func (p *cspAuthProvider) Login() error {
	return errors.New("not yet implemented")
}

type cspRoundTripper struct {
	tokenSource  oauth2.TokenSource
	roundTripper http.RoundTripper
}

func (r *cspRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(req.Header.Get(authHeader)) != 0 {
		return r.roundTripper.RoundTrip(req)
	}

	token, err := r.tokenSource.Token()
	if err != nil {
		klog.Errorf("Failed to acquire a token: %v", err)
		return nil, fmt.Errorf("acquiring a token for authorization header: %v", err)
	}

	// clone the request in order to avoid modifying the headers of the original request
	req2 := new(http.Request)
	*req2 = *req
	req2.Header = make(http.Header, len(req.Header))
	for k, s := range req.Header {
		req2.Header[k] = append([]string(nil), s...)
	}

	req2.Header.Set(authHeader, fmt.Sprintf("%s %s", token.Type(), token.AccessToken))

	return r.roundTripper.RoundTrip(req2)
}
