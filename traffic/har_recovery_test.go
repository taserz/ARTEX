package traffic

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestHARReimportRecoversMissingSearchEntry(t *testing.T) {
	tr, dir := openTraffic(t)
	if !tr.fts {
		t.Skip("driver does not have FTS5 enabled")
	}
	const marker = "operator-recovery-body-marker"
	entry := HAREntry{
		StartedDateTime: "2026-05-01T10:00:00Z",
		Request: HARRequest{
			Method:  "GET",
			URL:     "https://archive.example.test/record",
			Headers: []HARHeader{{Name: "X-Original", Value: "operator-record"}},
		},
		Response: HARResponse{
			Status: 200,
			Content: HARContent{
				MimeType: "text/plain",
				Text:     strings.Repeat("a", maxInlineBody) + marker,
			},
		},
	}
	importEntry := func(e HAREntry, imported, skipped, reindexed int, failure string) {
		t.Helper()
		raw, err := json.Marshal(HAR{Log: &HARLog{Version: HARVersion, Entries: []HAREntry{e}}})
		if err != nil {
			t.Fatal(err)
		}
		got, err := tr.ImportHAR(raw, HARImportOptions{})
		if err != nil || got.Imported != imported || got.Skipped != skipped || got.Reindexed != reindexed {
			t.Fatalf("ImportHAR = (%+v, %v), want imported=%d skipped=%d reindexed=%d", got, err, imported, skipped, reindexed)
		}
		if failure == "" && got.Failed != 0 {
			t.Fatalf("ImportHAR unexpectedly reported errors: %+v", got.Errors)
		}
		if failure != "" && (got.Failed != 1 || len(got.Errors) != 1 || got.Errors[0].Reason != failure) {
			t.Fatalf("ImportHAR = %+v, want failure %q", got, failure)
		}
	}
	importEntry(entry, 1, 0, 0, "")
	id := onlyExchangeID(t, tr)
	var rowID int64
	if err := tr.DB().QueryRow(`SELECT rowid FROM exchanges WHERE id=?`, id).Scan(&rowID); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.DB().Exec(`DELETE FROM ex_fts WHERE rowid=?`, rowID); err != nil {
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
	assertSearch := func(term string, want int) {
		t.Helper()
		rows, total, err := tr.Page(PageQuery{Body: term, RespMin: -1, RespMax: -1}, 0, 10)
		if err != nil || total != want || len(rows) != want {
			t.Fatalf("body search for %q = (%d rows, %d total, %v), want %d", term, len(rows), total, err, want)
		}
		if want == 1 && rows[0].ID != id {
			t.Fatalf("body search returned %q, want original exchange %q", rows[0].ID, id)
		}
	}

	reopen()
	assertSearch(marker, 0)
	changedHeaders := entry
	changedHeaders.Request.Headers = []HARHeader{{Name: "X-Original", Value: "changed-header-marker"}}
	importEntry(changedHeaders, 0, 1, 0, "")
	assertSearch("changed-header-marker", 0)
	changedBody := entry
	changedBody.ArtexExchangeID = id
	changedBody.Response.Content.Text = "changed-body-marker"
	importEntry(changedBody, 0, 1, 0, "")
	assertSearch("changed-body-marker", 0)
	assertSearch(marker, 0)

	var hash string
	if err := tr.DB().QueryRow(`SELECT resp_blob FROM exchange_bodies WHERE id=?`, id).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	path, err := tr.blobPath(hash)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := bytes.Clone(original)
	corrupt[0] ^= 1
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	importEntry(entry, 0, 0, 0, "stored HAR body failed integrity verification")
	assertSearch(marker, 0)
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	importEntry(entry, 0, 0, 1, "")
	reopen()
	assertSearch(marker, 1)
	importEntry(entry, 0, 1, 0, "")
	if got := onlyExchangeID(t, tr); got != id {
		t.Fatalf("stored exchange ID = %q, want %q", got, id)
	}
	var repairedRowID int64
	if err := tr.DB().QueryRow(`SELECT rowid FROM exchanges WHERE id=?`, id).Scan(&repairedRowID); err != nil || repairedRowID != rowID {
		t.Fatalf("stored rowid = (%d, %v), want original rowid %d", repairedRowID, err, rowID)
	}
	if count, err := tr.Count(); err != nil || count != 1 {
		t.Fatalf("stored exchange count = (%d, %v), want 1", count, err)
	}
}
