package hostup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func ptr16(v uint16) *uint16 { return &v }

// fakeAPI is an in-memory fake of the Hostup API v2 used in tests. Like the
// real API, it stores and returns full record names, while accepting
// zone-relative names in request bodies.
type fakeAPI struct {
	mu       sync.Mutex
	auth     string
	zones    map[string]apiZone
	records  map[string][]apiRecord
	nextID   int
	failWith func(r *http.Request) (status int, retryAfter string, ok bool)
}

func newFakeAPI(t *testing.T) (*fakeAPI, *httptest.Server) {
	t.Helper()
	f := &fakeAPI{
		auth:    "test-token",
		zones:   make(map[string]apiZone),
		records: make(map[string][]apiRecord),
	}
	srv := httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeAPI) addZone(id, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.zones[id] = apiZone{ID: id, Name: name, Status: "active", Kind: "linked"}
	f.records[id] = []apiRecord{}
}

func (f *fakeAPI) seed(zoneID string, recs ...apiRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range recs {
		if r.ID == "" {
			f.nextID++
			r.ID = fmt.Sprintf("drr_%d", f.nextID)
		}
		f.records[zoneID] = append(f.records[zoneID], r)
	}
}

func (f *fakeAPI) zoneRecords(zoneID string) []apiRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]apiRecord(nil), f.records[zoneID]...)
}

func (f *fakeAPI) fullName(zoneID, name string) string {
	zone := f.zones[zoneID].Name
	if name == "" || name == "@" {
		return zone
	}
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "." + zone
}

func (f *fakeAPI) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") != "Bearer "+f.auth {
		writeProblem(w, http.StatusUnauthorized, "unauthorized", "missing or invalid API key")
		return
	}
	if f.failWith != nil {
		if status, ra, ok := f.failWith(r); ok {
			if ra != "" {
				w.Header().Set("Retry-After", ra)
			}
			writeProblem(w, status, "injected_failure", "injected failure")
			return
		}
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v2")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 1 || parts[0] != "dns-zones" {
		writeProblem(w, http.StatusNotFound, "not_found", "unknown endpoint")
		return
	}
	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		f.handleListZones(w, r)
	case len(parts) == 3 && parts[2] == "records" && r.Method == http.MethodGet:
		f.handleListRecords(w, parts[1])
	case len(parts) == 3 && parts[2] == "records" && r.Method == http.MethodPost:
		f.handleCreateRecord(w, r, parts[1])
	case len(parts) == 4 && parts[2] == "records" && r.Method == http.MethodPut:
		f.handleUpdateRecord(w, r, parts[1], parts[3])
	case len(parts) == 4 && parts[2] == "records" && r.Method == http.MethodDelete:
		f.handleDeleteRecord(w, parts[1], parts[3])
	default:
		writeProblem(w, http.StatusNotFound, "not_found", "unknown endpoint")
	}
}

func (f *fakeAPI) handleListZones(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	f.mu.Lock()
	defer f.mu.Unlock()
	data := []apiZone{}
	for _, z := range f.zones {
		if name == "" || strings.EqualFold(z.Name, name) {
			data = append(data, z)
		}
	}
	json.NewEncoder(w).Encode(listZonesResponse{Data: data, HasMore: false, NextCursor: nil})
}

func (f *fakeAPI) handleListRecords(w http.ResponseWriter, zoneID string) {
	f.mu.Lock()
	zone, ok := f.zones[zoneID]
	if !ok {
		f.mu.Unlock()
		writeProblem(w, http.StatusNotFound, "dns_zone_not_found", "zone not found")
		return
	}
	recs := append([]apiRecord(nil), f.records[zoneID]...)
	f.mu.Unlock()
	json.NewEncoder(w).Encode(zoneRecordsResponse{Zone: zone, Records: recs})
}

func (f *fakeAPI) handleCreateRecord(w http.ResponseWriter, r *http.Request, zoneID string) {
	var rec apiRecord
	if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "bad body")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.zones[zoneID]; !ok {
		writeProblem(w, http.StatusNotFound, "dns_zone_not_found", "zone not found")
		return
	}
	rec.Name = f.fullName(zoneID, rec.Name)
	for _, ex := range f.records[zoneID] {
		if ex.Type == rec.Type && ex.Name == rec.Name && ex.Value == rec.Value {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(ex)
			return
		}
	}
	f.nextID++
	rec.ID = fmt.Sprintf("drr_%d", f.nextID)
	f.records[zoneID] = append(f.records[zoneID], rec)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(rec)
}

func (f *fakeAPI) handleUpdateRecord(w http.ResponseWriter, r *http.Request, zoneID, recordID string) {
	var rec apiRecord
	if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "bad body")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.zones[zoneID]; !ok {
		writeProblem(w, http.StatusNotFound, "dns_zone_not_found", "zone not found")
		return
	}
	for i, ex := range f.records[zoneID] {
		if ex.ID == recordID {
			rec.ID = recordID
			rec.Name = f.fullName(zoneID, rec.Name)
			f.records[zoneID][i] = rec
			json.NewEncoder(w).Encode(rec)
			return
		}
	}
	writeProblem(w, http.StatusNotFound, "dns_record_not_found", "record not found")
}

func (f *fakeAPI) handleDeleteRecord(w http.ResponseWriter, zoneID, recordID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	recs := f.records[zoneID]
	for i, ex := range recs {
		if ex.ID == recordID {
			f.records[zoneID] = append(recs[:i], recs[i+1:]...)
			break
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeProblem(w http.ResponseWriter, status int, code, detail string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"type":   "https://developer.hostup.se/errors/" + code,
		"title":  http.StatusText(status),
		"status": status,
		"code":   code,
		"detail": detail,
	})
}

func newTestProvider(srv *httptest.Server) *Provider {
	return &Provider{
		APIToken: "test-token",
		baseURL:  srv.URL + "/api/v2",
	}
}

func findRecord(t *testing.T, recs []libdns.Record, name, typ string) libdns.Record {
	t.Helper()
	for _, r := range recs {
		rr := r.RR()
		if rr.Name == name && rr.Type == typ {
			return r
		}
	}
	t.Fatalf("no %s record at %q in %v", typ, name, recs)
	return nil
}

func TestGetRecords(t *testing.T) {
	fake, srv := newFakeAPI(t)
	fake.addZone("zone_1", "example.com")
	fake.seed("zone_1",
		apiRecord{ID: "drr_1", Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 3600},
		apiRecord{ID: "drr_2", Type: "AAAA", Name: "www.example.com", Value: "2001:db8::1", TTL: 600},
		apiRecord{ID: "drr_3", Type: "TXT", Name: "_dmarc.example.com", Value: "v=DMARC1; p=none", TTL: 3600},
		apiRecord{ID: "drr_4", Type: "MX", Name: "example.com", Value: "mail.example.com", TTL: 3600, Priority: ptr16(10)},
		apiRecord{ID: "drr_5", Type: "SRV", Name: "_sip._tcp.example.com", Value: "sip.example.com", TTL: 300, Priority: ptr16(10), Weight: ptr16(5), Port: ptr16(5060)},
		apiRecord{ID: "drr_6", Type: "CNAME", Name: "www2.example.com", Value: "www.example.com", TTL: 3600},
		apiRecord{ID: "drr_7", Type: "NS", Name: "example.com", Value: "ns1.hostup.se", TTL: 86400},
		apiRecord{ID: "drr_8", Type: "CAA", Name: "example.com", Value: `0 issue "letsencrypt.org"`, TTL: 3600},
	)

	p := newTestProvider(srv)
	recs, err := p.GetRecords(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("GetRecords: %v", err)
	}
	if len(recs) != 8 {
		t.Fatalf("expected 8 records, got %d: %v", len(recs), recs)
	}

	a, ok := findRecord(t, recs, "@", "A").(libdns.Address)
	if !ok {
		t.Fatalf("apex A record is %T, want libdns.Address", findRecord(t, recs, "@", "A"))
	}
	if a.IP != netip.MustParseAddr("192.0.2.1") || a.TTL != time.Hour {
		t.Errorf("bad A record: %+v", a)
	}

	aaaa, ok := findRecord(t, recs, "www", "AAAA").(libdns.Address)
	if !ok || aaaa.IP != netip.MustParseAddr("2001:db8::1") || aaaa.TTL != 10*time.Minute {
		t.Errorf("bad AAAA record: %+v", findRecord(t, recs, "www", "AAAA"))
	}

	txt, ok := findRecord(t, recs, "_dmarc", "TXT").(libdns.TXT)
	if !ok || txt.Text != "v=DMARC1; p=none" {
		t.Errorf("bad TXT record: %+v", findRecord(t, recs, "_dmarc", "TXT"))
	}

	mx, ok := findRecord(t, recs, "@", "MX").(libdns.MX)
	if !ok || mx.Preference != 10 || mx.Target != "mail.example.com" {
		t.Errorf("bad MX record: %+v", findRecord(t, recs, "@", "MX"))
	}

	srvRec, ok := findRecord(t, recs, "_sip._tcp", "SRV").(libdns.SRV)
	if !ok || srvRec.Service != "sip" || srvRec.Transport != "tcp" || srvRec.Name != "@" ||
		srvRec.Priority != 10 || srvRec.Weight != 5 || srvRec.Port != 5060 || srvRec.Target != "sip.example.com" {
		t.Errorf("bad SRV record: %+v", findRecord(t, recs, "_sip._tcp", "SRV"))
	}

	cname, ok := findRecord(t, recs, "www2", "CNAME").(libdns.CNAME)
	if !ok || cname.Target != "www.example.com" {
		t.Errorf("bad CNAME record: %+v", findRecord(t, recs, "www2", "CNAME"))
	}

	ns, ok := findRecord(t, recs, "@", "NS").(libdns.NS)
	if !ok || ns.Target != "ns1.hostup.se" || ns.TTL != 24*time.Hour {
		t.Errorf("bad NS record: %+v", findRecord(t, recs, "@", "NS"))
	}

	caa, ok := findRecord(t, recs, "@", "CAA").(libdns.CAA)
	if !ok || caa.Flags != 0 || caa.Tag != "issue" || caa.Value != "letsencrypt.org" {
		t.Errorf("bad CAA record: %+v", findRecord(t, recs, "@", "CAA"))
	}
}

func TestAppendRecords(t *testing.T) {
	fake, srv := newFakeAPI(t)
	fake.addZone("zone_1", "example.com")

	p := newTestProvider(srv)
	appended, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "token123", TTL: 120 * time.Second},
		libdns.Address{Name: "www.example.com.", IP: netip.MustParseAddr("192.0.2.10"), TTL: time.Hour},
		libdns.MX{Name: "@", Preference: 20, Target: "mx2.example.com.", TTL: 3600 * time.Second},
	})
	if err != nil {
		t.Fatalf("AppendRecords: %v", err)
	}
	if len(appended) != 3 {
		t.Fatalf("expected 3 appended records, got %d", len(appended))
	}

	stored := fake.zoneRecords("zone_1")
	if len(stored) != 3 {
		t.Fatalf("expected 3 stored records, got %d: %v", len(stored), stored)
	}
	names := map[string]apiRecord{}
	for _, r := range stored {
		names[r.Name] = r
	}
	if r, ok := names["_acme-challenge.example.com"]; !ok || r.Type != "TXT" || r.Value != "token123" || r.TTL != 120 {
		t.Errorf("TXT not stored with full name and relative input: %v (all: %v)", r, stored)
	}
	if r, ok := names["www.example.com"]; !ok || r.Type != "A" || r.Value != "192.0.2.10" {
		t.Errorf("absolute input name not normalized: %v (all: %v)", r, stored)
	}
	if r, ok := names["example.com"]; !ok || r.Type != "MX" || r.Value != "mx2.example.com" || r.Priority == nil || *r.Priority != 20 {
		t.Errorf("MX not stored correctly (trailing dot should be trimmed): %v", r)
	}

	// appended records come back as libdns structs with relative names
	txt, ok := appended[0].(libdns.TXT)
	if !ok || txt.Name != "_acme-challenge" || txt.Text != "token123" || txt.TTL != 120*time.Second {
		t.Errorf("bad appended TXT: %+v", appended[0])
	}
}

func TestSetRecords(t *testing.T) {
	fake, srv := newFakeAPI(t)
	fake.addZone("zone_1", "example.com")
	fake.seed("zone_1",
		apiRecord{ID: "drr_a1", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 3600},
		apiRecord{ID: "drr_a2", Type: "A", Name: "www.example.com", Value: "192.0.2.2", TTL: 3600},
		apiRecord{ID: "drr_t1", Type: "TXT", Name: "note.example.com", Value: "keep", TTL: 3600},
		apiRecord{ID: "drr_o1", Type: "TXT", Name: "other.example.com", Value: "untouched", TTL: 3600},
	)

	p := newTestProvider(srv)
	set, err := p.SetRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.Address{Name: "www", IP: netip.MustParseAddr("192.0.2.3"), TTL: 600 * time.Second},
		libdns.TXT{Name: "note", Text: "changed", TTL: 300 * time.Second},
	})
	if err != nil {
		t.Fatalf("SetRecords: %v", err)
	}
	if len(set) != 2 {
		t.Fatalf("expected 2 set records, got %d", len(set))
	}

	stored := fake.zoneRecords("zone_1")
	if len(stored) != 3 {
		t.Fatalf("expected 3 records after SetRecords, got %d: %v", len(stored), stored)
	}
	byNameType := map[string]apiRecord{}
	for _, r := range stored {
		byNameType[r.Type+" "+r.Name] = r
	}
	a, ok := byNameType["A www.example.com"]
	if !ok || a.Value != "192.0.2.3" || a.TTL != 600 {
		t.Errorf("A www not set correctly: %v (all: %v)", a, stored)
	}
	if _, ok := byNameType["TXT note.example.com"]; !ok {
		t.Errorf("TXT note missing: %v", stored)
	} else if byNameType["TXT note.example.com"].Value != "changed" {
		t.Errorf("TXT note not updated: %v", stored)
	}
	other, ok := byNameType["TXT other.example.com"]
	if !ok || other.Value != "untouched" || other.ID != "drr_o1" {
		t.Errorf("unrelated record was modified: %v", other)
	}

	// setting the same A record again with a new TTL updates in place (same ID)
	_, err = p.SetRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.Address{Name: "www", IP: netip.MustParseAddr("192.0.2.3"), TTL: 300 * time.Second},
	})
	if err != nil {
		t.Fatalf("SetRecords (update): %v", err)
	}
	stored = fake.zoneRecords("zone_1")
	for _, r := range stored {
		if r.Type == "A" && r.Name == "www.example.com" {
			if r.ID != a.ID {
				t.Errorf("expected in-place update (ID %s), got new record %s", a.ID, r.ID)
			}
			if r.TTL != 300 {
				t.Errorf("TTL not updated: %d", r.TTL)
			}
		}
	}
}

func TestDeleteRecords(t *testing.T) {
	fake, srv := newFakeAPI(t)
	fake.addZone("zone_1", "example.com")
	fake.seed("zone_1",
		apiRecord{ID: "drr_x", Type: "TXT", Name: "_acme.example.com", Value: "abc", TTL: 60},
		apiRecord{ID: "drr_y", Type: "TXT", Name: "_acme.example.com", Value: "def", TTL: 60},
		apiRecord{ID: "drr_z", Type: "A", Name: "www.example.com", Value: "192.0.2.1", TTL: 3600},
	)

	p := newTestProvider(srv)

	// exact match deletes only that record
	deleted, err := p.DeleteRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.TXT{Name: "_acme", Text: "abc", TTL: 60 * time.Second},
	})
	if err != nil {
		t.Fatalf("DeleteRecords: %v", err)
	}
	if len(deleted) != 1 {
		t.Fatalf("expected 1 deleted record, got %d: %v", len(deleted), deleted)
	}

	// wildcard on value (type given) deletes the remaining TXT at the name
	deleted, err = p.DeleteRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.RR{Name: "_acme", Type: "TXT"},
	})
	if err != nil {
		t.Fatalf("DeleteRecords wildcard: %v", err)
	}
	if len(deleted) != 1 {
		t.Fatalf("expected 1 deleted record, got %d: %v", len(deleted), deleted)
	}

	// wildcard on type and value: zero-IP Address deletes the A record
	deleted, err = p.DeleteRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.Address{Name: "www"},
	})
	if err != nil {
		t.Fatalf("DeleteRecords wildcard address: %v", err)
	}
	if len(deleted) != 1 || deleted[0].RR().Type != "A" {
		t.Fatalf("expected the A record to be deleted, got %v", deleted)
	}

	// deleting something that does not exist is silently ignored
	deleted, err = p.DeleteRecords(context.Background(), "example.com.", []libdns.Record{
		libdns.TXT{Name: "nope", Text: "nothing"},
	})
	if err != nil {
		t.Fatalf("DeleteRecords non-existent: %v", err)
	}
	if len(deleted) != 0 {
		t.Fatalf("expected no deleted records, got %v", deleted)
	}
	if n := len(fake.zoneRecords("zone_1")); n != 0 {
		t.Fatalf("expected empty zone, got %d records", n)
	}
}

func TestListZones(t *testing.T) {
	fake, srv := newFakeAPI(t)
	fake.addZone("zone_1", "example.com")
	fake.addZone("zone_2", "example.org")

	p := newTestProvider(srv)
	zones, err := p.ListZones(context.Background())
	if err != nil {
		t.Fatalf("ListZones: %v", err)
	}
	if len(zones) != 2 {
		t.Fatalf("expected 2 zones, got %v", zones)
	}
	got := map[string]bool{}
	for _, z := range zones {
		got[z.Name] = true
	}
	if !got["example.com."] || !got["example.org."] {
		t.Errorf("unexpected zones (want trailing dots): %v", zones)
	}
}

func TestZoneNotFound(t *testing.T) {
	_, srv := newFakeAPI(t)
	p := newTestProvider(srv)
	_, err := p.GetRecords(context.Background(), "nope.example.")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected zone-not-found error, got %v", err)
	}
}

func TestAPIError(t *testing.T) {
	_, srv := newFakeAPI(t)
	p := newTestProvider(srv)
	p.APIToken = "wrong-token"
	_, err := p.GetRecords(context.Background(), "example.com.")
	if err == nil {
		t.Fatal("expected an error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.Status != 401 || apiErr.Code != "unauthorized" {
		t.Errorf("unexpected APIError: %+v", apiErr)
	}
}

func TestRetries(t *testing.T) {
	fake, srv := newFakeAPI(t)
	fake.addZone("zone_1", "example.com")
	fake.seed("zone_1", apiRecord{ID: "drr_1", Type: "A", Name: "example.com", Value: "192.0.2.1", TTL: 3600})

	var mu sync.Mutex
	calls := 0
	fake.failWith = func(r *http.Request) (int, string, bool) {
		if !strings.HasSuffix(r.URL.Path, "/records") {
			return 0, "", false
		}
		mu.Lock()
		defer mu.Unlock()
		calls++
		switch calls {
		case 1:
			return 500, "", true
		case 2:
			return 429, "0", true
		default:
			return 0, "", false
		}
	}

	p := newTestProvider(srv)
	recs, err := p.GetRecords(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("GetRecords after retries: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %v", recs)
	}
	if calls != 3 {
		t.Errorf("expected 3 attempts, got %d", calls)
	}
}

func TestRetriesExhausted(t *testing.T) {
	fake, srv := newFakeAPI(t)
	fake.addZone("zone_1", "example.com")
	fake.failWith = func(r *http.Request) (int, string, bool) {
		return 500, "", true
	}

	p := newTestProvider(srv)
	_, err := p.GetRecords(context.Background(), "example.com.")
	if err == nil {
		t.Fatal("expected an error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 500 {
		t.Fatalf("expected 500 APIError, got %v", err)
	}
}

func TestConcurrentAppends(t *testing.T) {
	fake, srv := newFakeAPI(t)
	fake.addZone("zone_1", "example.com")

	p := newTestProvider(srv)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := p.AppendRecords(context.Background(), "example.com.", []libdns.Record{
				libdns.TXT{Name: fmt.Sprintf("_c%d", i), Text: fmt.Sprintf("v%d", i), TTL: 60 * time.Second},
			})
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent AppendRecords: %v", err)
		}
	}
	if n := len(fake.zoneRecords("zone_1")); n != 8 {
		t.Fatalf("expected 8 records, got %d", n)
	}
}
