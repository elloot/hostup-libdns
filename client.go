package hostup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// defaultBaseURL is the base URL of the public Hostup API v2.
const defaultBaseURL = "https://cloud.hostup.se/api/v2"

const (
	// maxRetries is how many times a request is retried after a connection
	// error, a 429, or a 5xx response.
	maxRetries = 3
	// retryBaseDelay is the backoff before the first retry; it doubles with
	// each subsequent attempt.
	retryBaseDelay = 300 * time.Millisecond
	// maxRetryDelay caps the wait between attempts, including Retry-After.
	maxRetryDelay = 5 * time.Second
)

// APIError is an error returned by the Hostup API, which reports errors as
// RFC 7807 Problem Details documents with a stable machine-readable code.
type APIError struct {
	Status int    `json:"status,omitempty"`
	Type   string `json:"type,omitempty"`
	Title  string `json:"title,omitempty"`
	Detail string `json:"detail,omitempty"`
	Code   string `json:"code,omitempty"`
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("hostup: API error (HTTP %d)", e.Status)
	if e.Code != "" {
		msg += " [" + e.Code + "]"
	}
	if e.Detail != "" {
		msg += ": " + e.Detail
	} else if e.Title != "" {
		msg += ": " + e.Title
	}
	return msg
}

// do performs an HTTP request against the Hostup API, retrying connection
// errors, 429 and 5xx responses with backoff (honoring Retry-After). If out
// is non-nil, a successful response body is decoded into it.
func (p *Provider) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var bodyBytes []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("hostup: failed to encode request body: %w", err)
		}
		bodyBytes = b
	}

	reqURL := p.getBaseURL() + path
	if len(query) > 0 {
		reqURL += "?" + query.Encode()
	}

	var lastErr error
	var retryAfter time.Duration
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			delay := retryBaseDelay << (attempt - 1)
			if retryAfter > delay {
				delay = retryAfter
			}
			if delay > maxRetryDelay {
				delay = maxRetryDelay
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}

		var reqBody io.Reader
		if bodyBytes != nil {
			reqBody = bytes.NewReader(bodyBytes)
		}
		req, err := http.NewRequestWithContext(ctx, method, reqURL, reqBody)
		if err != nil {
			return fmt.Errorf("hostup: failed to build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+p.APIToken)
		req.Header.Set("Accept", "application/json")
		if bodyBytes != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := p.getHTTPClient().Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			lastErr = fmt.Errorf("hostup: request failed: %w", err)
			retryAfter = 0
			continue
		}
		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("hostup: failed to read response body: %w", err)
			retryAfter = 0
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = apiErrorFrom(resp.StatusCode, respBody)
			retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
			if attempt == maxRetries {
				return lastErr
			}
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return apiErrorFrom(resp.StatusCode, respBody)
		}

		if out == nil || len(respBody) == 0 {
			return nil
		}
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("hostup: failed to decode response (HTTP %d): %w", resp.StatusCode, err)
		}
		return nil
	}
	return lastErr
}

// apiErrorFrom builds an APIError from an HTTP status code and response body.
func apiErrorFrom(status int, body []byte) *APIError {
	ae := &APIError{Status: status}
	if len(body) > 0 {
		var pd APIError
		if err := json.Unmarshal(body, &pd); err == nil {
			if pd.Status != 0 {
				ae.Status = pd.Status
			}
			ae.Type, ae.Title, ae.Detail, ae.Code = pd.Type, pd.Title, pd.Detail, pd.Code
		}
	}
	if ae.Detail == "" && ae.Title == "" {
		ae.Title = http.StatusText(status)
	}
	return ae
}

// parseRetryAfter parses a Retry-After header value (delta-seconds or HTTP-date).
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return time.Until(t)
	}
	return 0
}

// listZones returns the DNS zones on the account, or only the zone with the
// given name if name is non-empty.
func (p *Provider) listZones(ctx context.Context, name string) ([]apiZone, error) {
	query := url.Values{}
	query.Set("limit", "1000")
	if name != "" {
		query.Set("name", name)
	}
	var zones []apiZone
	for {
		var resp listZonesResponse
		if err := p.do(ctx, http.MethodGet, "/dns-zones", query, nil, &resp); err != nil {
			return nil, err
		}
		zones = append(zones, resp.Data...)
		if !resp.HasMore || resp.NextCursor == nil || *resp.NextCursor == "" {
			return zones, nil
		}
		query.Set("cursor", *resp.NextCursor)
	}
}

// listZoneRecords returns all records of the zone with the given ID.
func (p *Provider) listZoneRecords(ctx context.Context, zoneID string) ([]apiRecord, error) {
	var resp zoneRecordsResponse
	path := "/dns-zones/" + url.PathEscape(zoneID) + "/records"
	if err := p.do(ctx, http.MethodGet, path, nil, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Records, nil
}

// createRecord creates one record in the zone and returns the created record.
func (p *Provider) createRecord(ctx context.Context, zoneID string, rec apiRecord) (*apiRecord, error) {
	rec.ID = ""
	var out apiRecord
	path := "/dns-zones/" + url.PathEscape(zoneID) + "/records"
	if err := p.do(ctx, http.MethodPost, path, nil, rec, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// updateRecord replaces the record recordID in the zone with rec.
func (p *Provider) updateRecord(ctx context.Context, zoneID, recordID string, rec apiRecord) (*apiRecord, error) {
	rec.ID = ""
	var out apiRecord
	path := "/dns-zones/" + url.PathEscape(zoneID) + "/records/" + url.PathEscape(recordID)
	if err := p.do(ctx, http.MethodPut, path, nil, rec, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// deleteRecord deletes the record recordID from the zone.
func (p *Provider) deleteRecord(ctx context.Context, zoneID, recordID string) error {
	path := "/dns-zones/" + url.PathEscape(zoneID) + "/records/" + url.PathEscape(recordID)
	return p.do(ctx, http.MethodDelete, path, nil, nil, nil)
}
