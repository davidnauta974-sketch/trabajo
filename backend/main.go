package main

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var web embed.FS

type task struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
}
type application struct {
	key   string
	mu    sync.Mutex
	tasks []task
}

func (a *application) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		page, _ := web.ReadFile("web/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(page)
	})
	mux.HandleFunc("/api/tasks", a.authorized(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			a.mu.Lock()
			defer a.mu.Unlock()
			tasks := append([]task{}, a.tasks...)
			respond(w, 200, tasks)
		case http.MethodPost:
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				respond(w, 415, map[string]string{"error": "Usa application/json"})
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 4096)
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()
			var data struct {
				Title string `json:"title"`
			}
			if err := dec.Decode(&data); err != nil {
				var limit *http.MaxBytesError
				if errors.As(err, &limit) {
					respond(w, 413, map[string]string{"error": "Solicitud demasiado grande"})
				} else {
					respond(w, 400, map[string]string{"error": "JSON no válido"})
				}
				return
			}
			if dec.Decode(&struct{}{}) != io.EOF {
				respond(w, 400, map[string]string{"error": "Solo se admite un objeto JSON"})
				return
			}
			title := strings.TrimSpace(data.Title)
			if len([]rune(title)) < 3 || len([]rune(title)) > 120 {
				respond(w, 400, map[string]string{"error": "El título debe tener entre 3 y 120 caracteres"})
				return
			}
			a.mu.Lock()
			defer a.mu.Unlock()
			if len(a.tasks) >= 1000 {
				respond(w, 409, map[string]string{"error": "Límite de la demostración alcanzado"})
				return
			}
			entry := task{len(a.tasks) + 1, title}
			a.tasks = append(a.tasks, entry)
			respond(w, 201, entry)
		default:
			w.Header().Set("Allow", "GET, POST")
			respond(w, 405, map[string]string{"error": "Método no permitido"})
		}
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}
func (a *application) authorized(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provided, hasBearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !hasBearer || a.key == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(a.key)) != 1 {
			respond(w, 401, map[string]string{"error": "Credencial no válida"})
			return
		}
		next(w, r)
	}
}
func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}
func loadKey(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(string(data))
	if len(key) < 24 {
		return "", errors.New("el secreto debe contener al menos 24 caracteres")
	}
	return key, nil
}
func main() {
	path := os.Getenv("API_KEY_FILE")
	if path == "" {
		path = "/run/secrets/api_key"
	}
	key, err := loadKey(path)
	if err != nil {
		log.Fatal("No se pudo cargar un secreto válido desde API_KEY_FILE")
	}
	addr := os.Getenv("APP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	a := &application{key: key}
	server := &http.Server{Addr: addr, Handler: a.routes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	log.Printf("Aplicación de laboratorio escuchando en %s", addr)
	log.Fatal(server.ListenAndServe())
}
