package infrared

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const APIPassword = "a671WwcKgFsvJ5aI"

type APIServer struct {
	gateway *Gateway
	bind    string
}

type PlayerStatsResponse struct {
	TotalPlayers int                    `json:"total_players"`
	Servers      []ServerPlayerStats    `json:"servers"`
	Timestamp    string                 `json:"timestamp"`
}

type ServerPlayerStats struct {
	ServerName string `json:"server_name"`
	Players    int    `json:"players"`
}

func NewAPIServer(gateway *Gateway, bind string) *APIServer {
	return &APIServer{
		gateway: gateway,
		bind:    bind,
	}
}

func (api *APIServer) Start() error {
	mux := http.NewServeMux()
	
	// Add CORS middleware
	corsHandler := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			
			next(w, r)
		}
	}
	
	// Player stats endpoint
	mux.HandleFunc("/api/players", corsHandler(api.handlePlayerStats))
	
	// Health check endpoint (no auth required)
	mux.HandleFunc("/api/health", corsHandler(api.handleHealth))
	
	log.Printf("Starting API server on %s", api.bind)
	return http.ListenAndServe(api.bind, mux)
}

func (api *APIServer) handlePlayerStats(w http.ResponseWriter, r *http.Request) {
	// Check authentication
	if !api.authenticate(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	stats := api.getPlayerStats()
	
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		log.Printf("Failed to encode player stats: %s", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func (api *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	health := map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"version":   "infrared-proxy",
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

func (api *APIServer) authenticate(r *http.Request) bool {
	// Check for password in query parameter
	password := r.URL.Query().Get("password")
	if password == APIPassword {
		return true
	}
	
	// Check for password in Authorization header
	auth := r.Header.Get("Authorization")
	if auth == "Bearer "+APIPassword {
		return true
	}
	
	// Check for password in custom header
	if r.Header.Get("X-API-Password") == APIPassword {
		return true
	}
	
	return false
}

func (api *APIServer) getPlayerStats() PlayerStatsResponse {
	var totalPlayers int
	var servers []ServerPlayerStats
	serverStats := make(map[string]int)
	
	// Collect metrics from Prometheus
	metricFamilies, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		log.Printf("Failed to gather metrics: %s", err)
		return PlayerStatsResponse{
			TotalPlayers: 0,
			Servers:      []ServerPlayerStats{},
			Timestamp:    time.Now().UTC().Format(time.RFC3339),
		}
	}
	
	// Parse the infrared_connected metric
	for _, mf := range metricFamilies {
		if mf.GetName() == "infrared_connected" {
			for _, metric := range mf.GetMetric() {
				var serverName string
				playerCount := int(metric.GetGauge().GetValue())
				
				// Extract server name from labels
				for _, label := range metric.GetLabel() {
					if label.GetName() == "host" {
						serverName = label.GetValue()
						break
					}
				}
				
				if serverName != "" && playerCount > 0 {
					serverStats[serverName] += playerCount
					totalPlayers += playerCount
				}
			}
		}
	}
	
	// Convert map to slice
	for serverName, playerCount := range serverStats {
		servers = append(servers, ServerPlayerStats{
			ServerName: serverName,
			Players:    playerCount,
		})
	}
	
	// Also include servers with 0 players from the gateway's proxy list
	api.addZeroPlayerServers(&servers, serverStats)
	
	return PlayerStatsResponse{
		TotalPlayers: totalPlayers,
		Servers:      servers,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
	}
}

func (api *APIServer) addZeroPlayerServers(servers *[]ServerPlayerStats, existingStats map[string]int) {
	// Add servers with 0 players from the main proxy list
	api.gateway.Proxies.Range(func(k, v interface{}) bool {
		proxy := v.(*Proxy)
		serverName := proxy.DomainName()
		
		// Only add if not already in the list
		if _, exists := existingStats[serverName]; !exists {
			*servers = append(*servers, ServerPlayerStats{
				ServerName: serverName,
				Players:    0,
			})
		}
		return true
	})
	
	// Add servers with 0 players from API-managed proxies
	api.gateway.apiProxiesMutex.RLock()
	for _, proxy := range api.gateway.apiProxies {
		serverName := proxy.DomainName()
		if _, exists := existingStats[serverName]; !exists {
			*servers = append(*servers, ServerPlayerStats{
				ServerName: serverName,
				Players:    0,
			})
		}
	}
	api.gateway.apiProxiesMutex.RUnlock()
}