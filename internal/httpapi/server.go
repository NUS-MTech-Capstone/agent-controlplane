package httpapi

import (
	"net/http"

	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/observability"
	"github.com/NUS-MTech-Capstone/agent-controlplane/internal/service"
)

type Server struct {
	svc              *service.Service
	mux              *http.ServeMux
	identityVerifier IdentityVerifier
}

func New(svc *service.Service, identityVerifier IdentityVerifier) *Server {
	s := &Server{svc: svc, mux: http.NewServeMux(), identityVerifier: identityVerifier}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	securityHeadersMiddleware(observability.RequestIDMiddleware(observability.LogRequests(apiVersionMiddleware(s.mux)))).ServeHTTP(w, r)
}
