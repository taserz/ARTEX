package traffic

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"strings"
)

// Keep recovered terms in a separate index used by the operator's Traffic view
// and its export filters. Only the exchange ID is retained alongside the terms.
const operatorFTSSchema = `CREATE VIRTUAL TABLE IF NOT EXISTS ex_operator_fts USING fts5(
  exchange_id UNINDEXED, content, tokenize='trigram',
  content='', contentless_delete=1, contentless_unindexed=1
);`

const savedSearchRecoveryBatchSize = 32

var ErrSavedSearchRecoveryUnavailable = errors.New("saved search recovery is unavailable")

func (t *Traffic) operatorSearchFilter(term string) (string, []any, bool) {
	cond, arg, ok := t.ftsFilter(term)
	if !ok {
		return "", nil, false
	}
	if !t.operatorFTS {
		return cond, []any{arg}, true
	}
	return `(` + cond + ` OR rowid IN (
  SELECT r.rowid FROM ex_operator_fts r JOIN exchanges e ON e.rowid=r.rowid AND e.id=r.exchange_id
  WHERE ex_operator_fts MATCH ? AND NOT EXISTS (SELECT 1 FROM ex_fts f WHERE f.rowid=r.rowid)
))`, []any{arg, arg}, true
}

type SavedSearchRecovery struct {
	Checked     int
	Recovered   int
	Unavailable int
	Through     int64 // last row ID when the operator started this pass
	NextAfter   int64 // resume after this row ID; zero when the pass is complete
}

type captureKey struct {
	rowid         int64
	id            string
	needsRecovery bool
}

// RecoverSavedSearch restores search entries from a batch of saved HTTP
// exchanges. It bounds each request by rows examined, including healthy rows,
// and commits each repair separately so interrupted passes can be retried.
func (t *Traffic) RecoverSavedSearch(ctx context.Context, after, through int64) (SavedSearchRecovery, error) {
	result := SavedSearchRecovery{Through: through}
	if t == nil || !t.operatorFTS {
		return result, ErrSavedSearchRecoveryUnavailable
	}
	if through == 0 {
		if err := t.db.QueryRowContext(ctx, `SELECT coalesce(max(rowid),0) FROM exchanges`).Scan(&result.Through); err != nil {
			return result, err
		}
	}
	keys, err := t.savedSearchRecoveryBatch(ctx, after, result.Through)
	if err != nil {
		return result, err
	}
	for _, key := range keys {
		result.Checked++
		if !key.needsRecovery {
			continue
		}
		recovered, unavailable, err := t.recoverSavedSearchEntry(ctx, key)
		if err != nil {
			return result, err
		}
		if recovered {
			result.Recovered++
		}
		if unavailable {
			result.Unavailable++
		}
	}
	if len(keys) == savedSearchRecoveryBatchSize && keys[len(keys)-1].rowid < result.Through {
		result.NextAfter = keys[len(keys)-1].rowid
	}
	return result, nil
}

func (t *Traffic) savedSearchRecoveryBatch(ctx context.Context, after, through int64) ([]captureKey, error) {
	rows, err := t.db.QueryContext(ctx, `SELECT e.rowid, e.id,
  coalesce(e.path='',0) AND NOT EXISTS (SELECT 1 FROM ex_fts f WHERE f.rowid=e.rowid)
  AND NOT EXISTS (SELECT 1 FROM ex_operator_fts r WHERE r.rowid=e.rowid AND r.exchange_id=e.id)
FROM exchanges e WHERE e.rowid>? AND e.rowid<=? ORDER BY e.rowid LIMIT ?`,
		after, through, savedSearchRecoveryBatchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []captureKey
	for rows.Next() {
		var key captureKey
		if err := rows.Scan(&key.rowid, &key.id, &key.needsRecovery); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (t *Traffic) recoverSavedSearchEntry(ctx context.Context, key captureKey) (recovered, unavailable bool, err error) {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	var exists int
	err = t.db.QueryRowContext(ctx, `SELECT 1 FROM exchanges e WHERE e.rowid=? AND e.id=? AND e.path=''
  AND NOT EXISTS (SELECT 1 FROM ex_fts f WHERE f.rowid=e.rowid)
  AND NOT EXISTS (SELECT 1 FROM ex_operator_fts r WHERE r.rowid=e.rowid AND r.exchange_id=e.id)`,
		key.rowid, key.id).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}

	var content string
	if err := t.readEvidence(key.id, func(e EvidenceExchange) error {
		_, reqHeaders := parseStoredRequestHead(e.ReqHead)
		req, err := recoveredBodyText(ctx, e.Request, e.ReqLen, e.ReqHash, findHeaderValue(reqHeaders, "Content-Type"))
		if err != nil {
			return err
		}
		resp, err := recoveredBodyText(ctx, e.Response, e.RespLen, e.RespHash, e.ContentType)
		if err != nil {
			return err
		}
		content = strings.Join([]string{e.URL, e.ReqHead, req, e.RespHead, resp}, "\n")
		return nil
	}); err != nil {
		if ctx.Err() != nil {
			return false, false, ctx.Err()
		}
		return false, true, nil
	}
	_, err = t.db.ExecContext(ctx, `INSERT OR REPLACE INTO ex_operator_fts(rowid,exchange_id,content) VALUES(?,?,?)`,
		key.rowid, key.id, content)
	return err == nil, false, err
}

// Keep only the same prefix as the normal index while verifying the complete
// stored body. A missing or corrupt blob must not produce a searchable preview.
func recoveredBodyText(ctx context.Context, body io.Reader, length int64, digest, contentType string) (string, error) {
	if length < 0 {
		return "", errors.New("invalid captured body length")
	}
	reader := recoveryReader{ctx, body}
	prefix := make([]byte, min(length, maxIndexBody))
	if _, err := io.ReadFull(reader, prefix); err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write(prefix)
	if _, err := io.CopyN(hash, reader, length-int64(len(prefix))); err != nil {
		return "", err
	}
	var extra [1]byte
	if _, err := io.ReadFull(reader, extra[:]); err != io.EOF {
		return "", errors.New("captured body length mismatch")
	}
	if digest != "" && hex.EncodeToString(hash.Sum(nil)) != digest {
		return "", errors.New("captured body hash mismatch")
	}
	if isBinaryBody(contentType, prefix) {
		return "", nil
	}
	return string(prefix), nil
}

type recoveryReader struct {
	ctx  context.Context
	body io.Reader
}

func (r recoveryReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.body.Read(p)
}
