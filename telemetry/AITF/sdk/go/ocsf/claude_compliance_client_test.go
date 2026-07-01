package ocsf

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIterActivitiesPaginates(t *testing.T) {
	var calls int
	var afterIDs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		afterIDs = append(afterIDs, r.URL.Query().Get("after_id"))
		w.Header().Set("Content-Type", "application/json")
		if calls == 0 {
			w.Write([]byte(`{"data":[{"id":"a1"},{"id":"a2"}],"has_more":true,"last_id":"a2"}`))
		} else {
			w.Write([]byte(`{"data":[{"id":"a3"}],"has_more":false,"last_id":"a3"}`))
		}
		calls++
	}))
	defer srv.Close()

	var got []string
	err := IterActivities(context.Background(), "k", ActivityFeedOptions{BaseURL: srv.URL},
		func(a map[string]interface{}) error {
			got = append(got, a["id"].(string))
			return nil
		})
	if err != nil {
		t.Fatalf("IterActivities returned error: %v", err)
	}
	if len(got) != 3 || got[0] != "a1" || got[1] != "a2" || got[2] != "a3" {
		t.Fatalf("handler received %v, want [a1 a2 a3]", got)
	}
	if calls != 2 {
		t.Fatalf("made %d requests, want 2", calls)
	}
	if len(afterIDs) != 2 || afterIDs[0] != "" || afterIDs[1] != "a2" {
		t.Fatalf("after_id sequence = %v, want [\"\" a2]", afterIDs)
	}
}

func TestIterActivitiesDefaultsLimit(t *testing.T) {
	var gotLimit string
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLimit = r.URL.Query().Get("limit")
		calls++
		w.Write([]byte(`{"data":[],"has_more":false,"last_id":""}`))
	}))
	defer srv.Close()

	err := IterActivities(context.Background(), "k", ActivityFeedOptions{BaseURL: srv.URL, Limit: 0},
		func(a map[string]interface{}) error { return nil })
	if err != nil {
		t.Fatalf("IterActivities returned error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("made %d requests, want 1", calls)
	}
	if gotLimit != "100" {
		t.Fatalf("limit = %q, want 100", gotLimit)
	}
}

func TestIterActivitiesInvalidLimit(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(`{"data":[],"has_more":false}`))
	}))
	defer srv.Close()

	err := IterActivities(context.Background(), "k", ActivityFeedOptions{BaseURL: srv.URL, Limit: 9999},
		func(a map[string]interface{}) error { return nil })
	if err == nil {
		t.Fatal("expected error for invalid limit, got nil")
	}
	if calls != 0 {
		t.Fatalf("made %d requests, want 0 (validation should happen before any request)", calls)
	}
}

func TestIterActivitiesHandlerErrorStops(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte(`{"data":[{"id":"a1"},{"id":"a2"}],"has_more":true,"last_id":"a2"}`))
	}))
	defer srv.Close()

	sentinel := errors.New("stop")
	var seen []string
	err := IterActivities(context.Background(), "k", ActivityFeedOptions{BaseURL: srv.URL},
		func(a map[string]interface{}) error {
			seen = append(seen, a["id"].(string))
			return sentinel
		})
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want sentinel", err)
	}
	if len(seen) != 1 || seen[0] != "a1" {
		t.Fatalf("handler saw %v, want [a1] (should stop on first error)", seen)
	}
	if calls != 1 {
		t.Fatalf("made %d requests, want 1", calls)
	}
}

func TestIterActivitiesNon2xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"nope"}`))
	}))
	defer srv.Close()

	err := IterActivities(context.Background(), "k", ActivityFeedOptions{BaseURL: srv.URL},
		func(a map[string]interface{}) error { return nil })
	if err == nil {
		t.Fatal("expected error for non-2xx response, got nil")
	}
}
