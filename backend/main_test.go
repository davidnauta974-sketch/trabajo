package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testKey = "FICTICIO_SOLO_EN_PRUEBAS_123456789"

func request(a *application, method, path, body, key string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if key != "" {
		r.Header.Set("Authorization", "Bearer "+key)
	}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	return w
}
func TestAuthorizationAndTaskFlow(t *testing.T) {
	a := &application{key: testKey}
	if w := request(a, "GET", "/healthz", "", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	for _, key := range []string{"", "incorrecto"} {
		if w := request(a, "GET", "/api/tasks", "", key); w.Code != 401 {
			t.Fatal(w.Code)
		}
	}
	w := request(a, "POST", "/api/tasks", `{"title":"Verificar políticas"}`, testKey)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = request(a, "GET", "/api/tasks", "", testKey)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Verificar políticas") {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestInputValidation(t *testing.T) {
	for _, data := range []string{`{"title":"a"}`, `{"title":"abc","admin":true}`, `{"title":"abc"}{}`, `not-json`} {
		a := &application{key: testKey}
		w := request(a, "POST", "/api/tasks", data, testKey)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", data, w.Code)
		}
		if len(a.tasks) != 0 {
			t.Fatal("Se modificaron datos con entrada inválida")
		}
	}
}
func TestLargeBodyRejected(t *testing.T) {
	a := &application{key: testKey}
	w := request(a, "POST", "/api/tasks", `{"title":"`+strings.Repeat("a", 5000)+`"}`, testKey)
	if w.Code != 413 {
		t.Fatal(w.Code)
	}
}
func TestMethodRestriction(t *testing.T) {
	a := &application{key: testKey}
	if w := request(a, "DELETE", "/api/tasks", "", testKey); w.Code != 405 {
		t.Fatal(w.Code)
	}
}
func TestMissingSecretFailsClosed(t *testing.T) {
	if _, e := loadKey(filepath.Join(t.TempDir(), "missing")); e == nil {
		t.Fatal("Se aceptó secreto inexistente")
	}
	p := filepath.Join(t.TempDir(), "key")
	os.WriteFile(p, []byte("corta"), 0600)
	if _, e := loadKey(p); e == nil {
		t.Fatal("Se aceptó secreto débil")
	}
}

func TestAuthorizationSchemeRequired(t *testing.T) {
	a := &application{key: testKey}
	r := httptest.NewRequest("GET", "/api/tasks", nil)
	r.Header.Set("Authorization", testKey)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("La clave sin esquema Bearer debe rechazarse")
	}
}
