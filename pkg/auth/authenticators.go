package auth

import (
	"fmt"
	"sync"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	authenticatorunion "k8s.io/apiserver/pkg/authentication/request/union"
	"k8s.io/klog/v2"
)

var handlersLock sync.Mutex
var handlers = make(map[string]authenticator.Request)

func RegisterAuthRequestHandler(name string, handler authenticator.Request) error {
	handlersLock.Lock()
	defer handlersLock.Unlock()
	if _, found := handlers[name]; found {
		return fmt.Errorf("auth handler %q was registered twice", name)
	}
	klog.V(4).InfoS("Registered Auth Handler", "name", name)
	handlers[name] = handler
	return nil
}

func UnionAuthRequest(authRequestHandler authenticator.Request) authenticator.Request {
	authRequestHandlers := []authenticator.Request{authRequestHandler}
	for _, handler := range handlers {
		authRequestHandlers = append(authRequestHandlers, handler)
	}
	return authenticatorunion.New(authRequestHandlers...)
}
