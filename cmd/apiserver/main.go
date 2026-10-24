package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	emailverifier "github.com/hanzoai/email-verifier"
	"github.com/julienschmidt/httprouter"
)

type VerificationStatus string

const (
	StatusClean       VerificationStatus = "clean"
	StatusBounced     VerificationStatus = "bounced"
	StatusBadSyntax   VerificationStatus = "bad_syntax"
	StatusBadNoMX     VerificationStatus = "bad_no_mx"
	StatusDisposable  VerificationStatus = "bad_disposable"
	StatusRoleAccount VerificationStatus = "role_account"
	StatusBlacklisted VerificationStatus = "blacklisted"
)

type VerifyResponse struct {
	Email      string             `json:"email"`
	Status     VerificationStatus `json:"status"`
	IsValid    bool               `json:"is_valid"`
	Reason     string             `json:"reason"`
	Domain     string             `json:"domain,omitempty"`
	HasMX      bool               `json:"has_mx"`
	Disposable bool               `json:"is_disposable"`
	Role       bool               `json:"is_role"`
	Free       bool               `json:"is_free"`
	Suggestion string             `json:"suggestion,omitempty"`
}

type BatchVerifyRequest struct {
	Email  string   `json:"email,omitempty"`
	Emails []string `json:"emails,omitempty"`
}

type BatchVerifyResponse struct {
	Results []VerifyResponse `json:"results"`
	Total   int              `json:"total"`
	Clean   int              `json:"clean"`
	Invalid int              `json:"invalid"`
}

type Server struct {
	verifier    *emailverifier.Verifier
	domainCache sync.Map
	blacklist   map[string]struct{}
	mu          sync.RWMutex
}

type DomainCacheEntry struct {
	HasMX bool
	Err   error
}

func NewServer() *Server {
	v := emailverifier.NewVerifier().EnableDomainSuggest()
	return &Server{
		verifier:  v,
		blacklist: make(map[string]struct{}),
	}
}

func (s *Server) checkMX(domain string) (bool, error) {
	if val, ok := s.domainCache.Load(domain); ok {
		entry := val.(DomainCacheEntry)
		return entry.HasMX, entry.Err
	}
	mx, err := s.verifier.CheckMX(domain)
	hasMX := false
	if mx != nil && mx.HasMXRecord {
		hasMX = true
	}
	s.domainCache.Store(domain, DomainCacheEntry{HasMX: hasMX, Err: err})
	return hasMX, err
}

func (s *Server) VerifyEmail(raw string) VerifyResponse {
	email := strings.ToLower(strings.TrimSpace(raw))
	res := VerifyResponse{
		Email:   email,
		Status:  StatusClean,
		IsValid: false,
	}

	if email == "" {
		res.Status = StatusBadSyntax
		res.Reason = "empty_email_address"
		return res
	}

	// 1. Blacklist check
	s.mu.RLock()
	_, blacklisted := s.blacklist[email]
	s.mu.RUnlock()
	if blacklisted {
		res.Status = StatusBlacklisted
		res.Reason = "suppressed_by_blacklist"
		return res
	}

	// 2. Syntax validation
	syntax := s.verifier.ParseAddress(email)
	if !syntax.Valid {
		res.Status = StatusBadSyntax
		res.Reason = "invalid_rfc5322_syntax"
		return res
	}

	res.Domain = syntax.Domain
	res.Free = s.verifier.IsFreeDomain(syntax.Domain)
	res.Role = s.verifier.IsRoleAccount(syntax.Username)
	res.Disposable = s.verifier.IsDisposable(syntax.Domain)
	res.Suggestion = s.verifier.SuggestDomain(syntax.Domain)

	// 3. Disposable domain detection
	if res.Disposable {
		res.Status = StatusDisposable
		res.Reason = "disposable_throwaway_domain"
		return res
	}

	// 4. DNS MX record check
	hasMX, err := s.checkMX(syntax.Domain)
	res.HasMX = hasMX
	if !hasMX || err != nil {
		res.Status = StatusBadNoMX
		if err != nil {
			res.Reason = "dns_mx_lookup_error"
		} else {
			res.Reason = "no_active_mx_records_found"
		}
		return res
	}

	// 5. Role account warning (e.g. admin@, info@, support@)
	if res.Role {
		res.Status = StatusRoleAccount
		res.Reason = "role_based_mailbox"
		// Role accounts have valid MX, but may not be direct developer inboxes
		res.IsValid = true
		return res
	}

	// 6. Clean deliverable address
	res.IsValid = true
	res.Status = StatusClean
	res.Reason = "verified_clean_active_mx"
	return res
}

func enableCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Origin, Accept")
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	enableCORS(w)
	w.Header().Set("Content-Type", "application/json")

	email := r.URL.Query().Get("email")
	if email == "" {
		email = r.URL.Query().Get("address")
	}

	if email == "" {
		http.Error(w, `{"error":"missing required query parameter 'email'"}`, http.StatusBadRequest)
		return
	}

	res := s.VerifyEmail(email)
	_ = json.NewEncoder(w).Encode(res)
}

func (s *Server) handlePostVerify(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	enableCORS(w)
	w.Header().Set("Content-Type", "application/json")

	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
	if err != nil {
		http.Error(w, `{"error":"unable to read request body"}`, http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req BatchVerifyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid json body"}`, http.StatusBadRequest)
		return
	}

	// Single email in JSON body
	if req.Email != "" && len(req.Emails) == 0 {
		res := s.VerifyEmail(req.Email)
		_ = json.NewEncoder(w).Encode(res)
		return
	}

	// Batch emails in JSON body
	if len(req.Emails) > 0 {
		if len(req.Emails) > 500 {
			http.Error(w, `{"error":"maximum batch size is 500 emails per request"}`, http.StatusBadRequest)
			return
		}

		results := make([]VerifyResponse, len(req.Emails))
		cleanCount := 0
		invalidCount := 0

		var wg sync.WaitGroup
		sem := make(chan struct{}, 32) // max 32 concurrent DNS workers per batch

		for i, em := range req.Emails {
			wg.Add(1)
			sem <- struct{}{}
			go func(idx int, emailStr string) {
				defer wg.Done()
				defer func() { <-sem }()
				results[idx] = s.VerifyEmail(emailStr)
			}(i, em)
		}
		wg.Wait()

		for _, r := range results {
			if r.IsValid {
				cleanCount++
			} else {
				invalidCount++
			}
		}

		resp := BatchVerifyResponse{
			Results: results,
			Total:   len(results),
			Clean:   cleanCount,
			Invalid: invalidCount,
		}
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	http.Error(w, `{"error":"must provide 'email' string or 'emails' array in body"}`, http.StatusBadRequest)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	enableCORS(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok","service":"email-verifier","provider":"hanzo"}`))
}

func (s *Server) handleOptions(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	enableCORS(w)
	w.WriteHeader(http.StatusNoContent)
}

func main() {
	srv := NewServer()
	router := httprouter.New()

	// OPTIONS pre-flight for browser requests
	router.GlobalOPTIONS = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w)
		w.WriteHeader(http.StatusNoContent)
	})

	// Health probes
	router.GET("/healthz", srv.handleHealth)
	router.GET("/readyz", srv.handleHealth)
	router.GET("/v1/email/health", srv.handleHealth)

	// API verify routes
	router.GET("/v1/email/verify", srv.handleVerify)
	router.POST("/v1/email/verify", srv.handlePostVerify)
	router.OPTIONS("/v1/email/verify", srv.handleOptions)



	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Printf("Starting Hanzo Email Verifier API on port %s...", port)
	log.Fatal(server.ListenAndServe())
}
