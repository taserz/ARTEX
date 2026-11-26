package server

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"

	"github.com/Autumn-27/artex/traffic"
)

type savedSearchRecoveryResponse struct {
	Checked     int    `json:"checked"`
	Recovered   int    `json:"recovered"`
	Unavailable int    `json:"unavailable"`
	Through     string `json:"through"`
	NextAfter   string `json:"next_after,omitempty"`
}

func (s *Server) recoverSavedTrafficSearch(w http.ResponseWriter, r *http.Request) {
	var after, through int64
	if r.URL.RawQuery != "" {
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || len(query) != 2 || len(query["after"]) != 1 || len(query["through"]) != 1 {
			writeErr(w, http.StatusBadRequest, "invalid traffic search recovery cursor")
			return
		}
		after, err = strconv.ParseInt(query.Get("after"), 10, 64)
		var throughErr error
		through, throughErr = strconv.ParseInt(query.Get("through"), 10, 64)
		if err != nil || throughErr != nil || after <= 0 || through <= after {
			writeErr(w, http.StatusBadRequest, "invalid traffic search recovery cursor")
			return
		}
	}

	result, err := s.m.Traffic().RecoverSavedSearch(r.Context(), after, through)
	if errors.Is(err, traffic.ErrSavedSearchRecoveryUnavailable) {
		writeErr(w, http.StatusServiceUnavailable, "traffic search recovery is unavailable")
		return
	}
	if err != nil {
		if r.Context().Err() == nil {
			slog.Error("[traffic] saved search recovery failed")
			writeErr(w, http.StatusInternalServerError, "traffic search recovery failed")
		}
		return
	}
	response := savedSearchRecoveryResponse{
		Checked:     result.Checked,
		Recovered:   result.Recovered,
		Unavailable: result.Unavailable,
		Through:     strconv.FormatInt(result.Through, 10),
	}
	if result.NextAfter > 0 {
		response.NextAfter = strconv.FormatInt(result.NextAfter, 10)
	}
	writeJSON(w, http.StatusOK, response)
}
