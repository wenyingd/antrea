package csp

import (
	"context"
	"errors"
	"fmt"
	"k8s.io/apiserver/pkg/authentication/user"
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
	scopePermKey       = "scope"
	namespaceKey       = "ns"
	clusterScope       = "cluster"
	userNamePrefix     = "userName"
)

type clientClaim struct {
	ClientID    string           `json:"azp"`
	OrgID       string           `json:"context_name"`
	Permissions []string         `json:"perms"`
	Issuer      string           `json:"iss"`
	Expiry      *jwt.NumericDate `json:"exp,omitempty"`
	IssuedAt    *jwt.NumericDate `json:"iat,omitempty"`
}

func (c *clientClaim) getScope() string {
	scope := c.getPermWithPrefix(scopePermKey, clusterScope)
	if scope == clusterScope {
		return scope
	}
	return strings.Trim(scope, fmt.Sprintf("%s_", namespaceKey))
}

func (c *clientClaim) getPermWithPrefix(prefix, defaultValue string) string {
	value := defaultValue
	for _, permStr := range c.Permissions {
		if strings.HasPrefix(permStr, prefix) {
			perm := strings.Split(permStr, ":")
			if len(perm) > 1 {
				value = perm[1]
				break
			}
		}
	}
	return value
}

type authenticationHandler struct {
	organizations sets.String
	clients       map[string]string
	audiences     authenticator.Audiences
	tm            cspauth.TokenManager
}

func (h *authenticationHandler) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	token := h.parseToken(req)
	if token == "" {
		return nil, false, errors.New("no token is found in the HTTP request header")
	}
	return h.validate(token)
}

func (h *authenticationHandler) parseToken(req *http.Request) string {
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

func (h *authenticationHandler) validate(tokenData string) (*authenticator.Response, bool, error) {
	valid, err := h.tm.Validate(context.Background(), tokenData)
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
		User:      h.parseUserInfoFromClaim(claim),
		Audiences: h.audiences,
	}, true, nil
}

func (h *authenticationHandler) parseUserInfoFromClaim(claim *clientClaim) user.Info {
	namespace := claim.getScope()
	groups := []string{
		authenticatedGroup,
		claim.OrgID,
		fmt.Sprintf("%s:%s", scopePermKey, namespace),
	}
	userName := h.getUserName(claim, namespace)
	return &user.DefaultInfo{
		Name:   userName,
		UID:    claim.ClientID,
		Groups: groups,
		Extra: map[string][]string{
			CSPTokenPermKey: claim.Permissions,
		},
	}
}

func (h *authenticationHandler) getUserName(claim *clientClaim, namespace string) string {
	userName := claim.getPermWithPrefix(userNamePrefix, "")
	if userName != "" {
		return userName
	}
	return h.getExternalNodeName(claim.ClientID)
}
