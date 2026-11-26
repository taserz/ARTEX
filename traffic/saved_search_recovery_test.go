package traffic

import (
	"os"
	"strings"
	"testing"
)

func TestRecoverSavedSearchRestoresOperatorSearch(t *testing.T) {
	tr, dir := openTraffic(t)
	if !tr.fts {
		t.Skip("driver does not have FTS5 enabled")
	}
	if !tr.operatorFTS {
		t.Fatal("operator full-text index did not initialize")
	}
	const host = "saved.example.test"
	const marker = "retained-capture-search-marker"
	body := strings.Repeat("a", maxInlineBody) + marker
	tr.record(newFlow(host, "GET", "/record", nil, []byte(body), withRespType("text/plain")))
	id := onlyExchangeID(t, tr)
	if _, err := tr.DB().Exec(`DELETE FROM ex_fts WHERE rowid=(SELECT rowid FROM exchanges WHERE id=?)`, id); err != nil {
		t.Fatal(err)
	}

	reopen := func() {
		t.Helper()
		if err := tr.Close(); err != nil {
			t.Fatal(err)
		}
		reopened, err := Open(dir, "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		tr = reopened
		t.Cleanup(func() { _ = reopened.Close() })
	}
	filter := PageQuery{Body: marker, RespMin: -1, RespMax: -1}
	assertPage := func(want int) {
		t.Helper()
		rows, total, err := tr.Page(filter, 0, 10)
		if err != nil || total != want || len(rows) != want {
			t.Fatalf("operator search returned %d rows and total %d, want %d (err=%v)", len(rows), total, want, err)
		}
		if want == 1 && rows[0].ID != id {
			t.Fatalf("operator search returned %q, want original exchange %q", rows[0].ID, id)
		}
	}

	reopen()
	assertPage(0)
	result, err := tr.RecoverSavedSearch(t.Context(), 0, 0)
	if err != nil || result.Checked != 1 || result.Recovered != 1 || result.Unavailable != 0 || result.NextAfter != 0 {
		t.Fatalf("recovery = (%+v, %v), want one recovered capture", result, err)
	}
	assertPage(1)
	_, exported, err := tr.ExportHAR(filter, HARExportOptions{})
	if err != nil || exported.Exported != 1 {
		t.Fatalf("filtered export returned %d entries, want one (err=%v)", exported.Exported, err)
	}
	rows, err := tr.query(host, "", marker, 0, 10)
	if err != nil || len(rows) != 0 {
		t.Fatalf("shared traffic query returned %d rows, want none (err=%v)", len(rows), err)
	}
	if count, err := tr.Count(); err != nil || count != 1 {
		t.Fatalf("store count = (%d, %v), want one exchange", count, err)
	}

	reopen()
	assertPage(1)
	result, err = tr.RecoverSavedSearch(t.Context(), 0, 0)
	if err != nil || result.Recovered != 0 || result.Unavailable != 0 {
		t.Fatalf("repeated recovery = (%+v, %v), want no work", result, err)
	}
	if count, err := tr.DeleteHost(host); err != nil || count != 1 {
		t.Fatalf("delete host = (%d, %v), want one deleted exchange", count, err)
	}
	var retained int
	if err := tr.DB().QueryRow(`SELECT count(*) FROM ex_operator_fts`).Scan(&retained); err != nil || retained != 0 {
		t.Fatalf("recovered entries after deletion = (%d, %v), want none", retained, err)
	}
	assertPage(0)
}

func TestRecoverSavedSearchResumesThroughOriginalHighWaterMark(t *testing.T) {
	tr, _ := openTraffic(t)
	if !tr.fts {
		t.Skip("driver does not have FTS5 enabled")
	}
	const host = "saved.example.test"
	for range savedSearchRecoveryBatchSize + 1 {
		tr.record(newFlow(host, "GET", "/record", nil, []byte("saved capture"), withRespType("text/plain")))
	}
	if _, err := tr.DB().Exec(`DELETE FROM ex_fts WHERE rowid=(SELECT max(rowid) FROM exchanges)`); err != nil {
		t.Fatal(err)
	}
	first, err := tr.RecoverSavedSearch(t.Context(), 0, 0)
	if err != nil || first.Checked != savedSearchRecoveryBatchSize || first.Recovered != 0 || first.NextAfter == 0 || first.NextAfter >= first.Through {
		t.Fatalf("first batch = (%+v, %v), want a cursor after the healthy rows", first, err)
	}

	tr.record(newFlow(host, "GET", "/new", nil, []byte("new saved capture"), withRespType("text/plain")))
	if _, err := tr.DB().Exec(`DELETE FROM ex_fts WHERE rowid=(SELECT max(rowid) FROM exchanges)`); err != nil {
		t.Fatal(err)
	}
	second, err := tr.RecoverSavedSearch(t.Context(), first.NextAfter, first.Through)
	if err != nil || second.Checked != 1 || second.Recovered != 1 || second.NextAfter != 0 || second.Through != first.Through {
		t.Fatalf("second batch = (%+v, %v), want only the last capture from the original pass", second, err)
	}
}

func TestRecoverSavedSearchSkipsMissingBody(t *testing.T) {
	tr, _ := openTraffic(t)
	if !tr.fts {
		t.Skip("driver does not have FTS5 enabled")
	}
	if !tr.operatorFTS {
		t.Fatal("operator full-text index did not initialize")
	}
	const host = "saved.example.test"
	const missing = "missing-body-preview-marker"
	const available = "unaffected-body-marker"
	tr.record(newFlow(host, "GET", "/missing", nil, []byte(missing+strings.Repeat("a", maxInlineBody)), withRespType("text/plain")))
	id := onlyExchangeID(t, tr)
	var hash string
	if err := tr.DB().QueryRow(`SELECT resp_blob FROM exchange_bodies WHERE id=?`, id).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	path, err := tr.blobPath(hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	tr.record(newFlow(host, "GET", "/available", nil, []byte(available), withRespType("text/plain")))
	if _, err := tr.DB().Exec(`DELETE FROM ex_fts`); err != nil {
		t.Fatal(err)
	}

	result, err := tr.RecoverSavedSearch(t.Context(), 0, 0)
	if err != nil || result.Checked != 2 || result.Recovered != 1 || result.Unavailable != 1 || result.NextAfter != 0 {
		t.Fatalf("recovery = (%+v, %v), want one unavailable and one recovered capture", result, err)
	}
	for _, tc := range []struct {
		term string
		want int
	}{{missing, 0}, {available, 1}} {
		_, total, err := tr.Page(PageQuery{Body: tc.term, RespMin: -1, RespMax: -1}, 0, 10)
		if err != nil || total != tc.want {
			t.Fatalf("operator search for %q returned total %d, want %d (err=%v)", tc.term, total, tc.want, err)
		}
	}
}
