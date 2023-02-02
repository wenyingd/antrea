package csp

import (
	"context"
	"errors"
	"net/http"
	"strings"

	cspauth "gitlab.eng.vmware.com/csp/go-framework/auth"
	"gopkg.in/square/go-jose.v2/jwt"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/authenticator"
)

const (
	CSPTokenPermKey    = "CSP-Permissions"
	authenticatedGroup = "system:authenticated"
)

type clientClaim struct {
	ClientID    string           `json:"azp"`
	OrgID       string           `json:"context_name"`
	Permissions []string         `json:"perms"`
	Issuer      string           `json:"iss"`
	Expiry      *jwt.NumericDate `json:"exp,omitempty"`
	IssuedAt    *jwt.NumericDate `json:"iat,omitempty"`
}

func (c *clientClaim) GetName() string {
	return c.ClientID
}

func (c *clientClaim) GetUID() string {
	return c.ClientID
}

func (c *clientClaim) GetGroups() []string {
	return []string{
		authenticatedGroup,
		c.OrgID,
	}
}

func (c *clientClaim) GetExtra() map[string][]string {
	return map[string][]string{
		CSPTokenPermKey: c.Permissions,
	}
}

type authHandler struct {
	organizations sets.String
	clients       map[string]string
	audiences     authenticator.Audiences
	tm            cspauth.TokenManager
}

func (a *authHandler) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	token := a.parseToken(req)
	if token == "" {
		return nil, false, errors.New("no token is found in the HTTP request header")
	}
	return a.validate(token)
}

func (a *authHandler) parseToken(req *http.Request) string {
	auth := strings.TrimSpace(req.Header.Get("Authorization"))
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 3)
	if len(parts) < 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}
	return parts[1]
}

func (a *authHandler) validate(tokenData string) (*authenticator.Response, bool, error) {
	valid, err := a.tm.Validate(context.Background(), tokenData)
	if err != nil {
		return nil, false, err
	}
	if !valid {
		return nil, false, nil
	}
	tok, err := jwt.ParseSigned(tokenData)
	if err != nil {
		return nil, false, err
	}
	claim := &clientClaim{}
	if err = tok.UnsafeClaimsWithoutVerification(claim); err != nil {
		return nil, false, err
	}
	return &authenticator.Response{
		User:      claim,
		Audiences: a.audiences,
	}, true, nil
}
