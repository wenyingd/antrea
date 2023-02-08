package csp

import (
	"context"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

type authorizationHandler struct {
	privilegedGroups sets.String
}

func (h *authorizationHandler) Authorize(ctx context.Context, a authorizer.Attributes) (authorized authorizer.Decision, reason string, err error) {
	if !a.IsResourceRequest() {
		return authorizer.DecisionNoOpinion, "", nil
	}
	return h.visitAuthRules(a)
}

func (h *authorizationHandler) visitAuthRules(a authorizer.Attributes) (authorizer.Decision, string, error) {
	user := a.GetUser()
	verb := a.GetVerb()
	resource := a.GetResource()
	subresource := a.GetSubresource()
	namespace := a.GetNamespace()
	path := a.GetPath()
}
