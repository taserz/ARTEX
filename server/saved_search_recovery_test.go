package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Autumn-27/artex/traffic"
)

func TestSavedTrafficSearchRecoveryEndpoint(t *testing.T) {
	tr, err := traffic.Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	s := &Server{m: &Manager{traffic: tr}, jwtKey: []byte("saved-traffic-recovery-test-key")}
	handler := s.Handler()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	const endpoint = "/api/traffic/search/recover"
	request := func(suffix string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, endpoint+suffix, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, endpoint, nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated recovery status = %d, want 401", unauthorized.Code)
	}
	for _, query := range []string{"?after=1", "?after=1&after=2&through=3", "?after=-1&through=3", "?after=3&through=3"} {
		if response := request(query); response.Code != http.StatusBadRequest {
			t.Fatalf("%s recovery status = %d, want 400", query, response.Code)
		}
	}

	if err := tr.RecordExternal(traffic.ExternalExchange{
		Method: "GET", URL: "https://saved.example.test/recovery", ResponseBody: "archived evidence",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.DB().Exec(`DELETE FROM ex_fts`); err != nil {
		t.Fatal(err)
	}
	response := request("")
	if response.Code != http.StatusOK {
		t.Fatalf("recovery status = %d, body = %s", response.Code, response.Body.String())
	}
	var result savedSearchRecoveryResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Checked != 1 || result.Recovered != 1 || result.Unavailable != 0 || result.Through != "1" || result.NextAfter != "" {
		t.Fatalf("unexpected response: %+v", result)
	}
}
