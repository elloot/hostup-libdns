// Package hostup implements the libdns interfaces for Hostup (https://hostup.se),
// using the public Hostup API v2 (https://developer.hostup.se/).
//
// An API key with the read:dns and write:dns scopes is required; create one
// in the Hostup dashboard under API keys.
//
// Zones are addressed by their domain name (e.g. "example.com.") and resolved
// to the API's zone ID on first use; the mapping is cached.
//
// Caveats:
//   - Record types A, AAAA, CNAME, MX, NS, SRV, TXT and CAA are mapped to the
//     corresponding libdns structs; ALIAS, TLSA, SOA and any other type unknown
//     to libdns are returned as libdns.RR values.
//   - Hostup accepts TTLs from 60 to 86400 seconds; a zero TTL is sent as the
//     API default of 3600 seconds.
//   - The CDN proxy state ("proxied") of A, AAAA and CNAME records is not
//     managed by this package.
package hostup

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with Hostup.
type Provider struct {
	// APIToken is a Hostup API key with the read:dns and write:dns scopes.
	APIToken string `json:"api_token,omitempty"`

	baseURL    string
	httpClient *http.Client

	mu        sync.Mutex
	zoneIDs   map[string]string
	zoneLocks map[string]*sync.Mutex
}

func (p *Provider) getBaseURL() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.baseURL != "" {
		return strings.TrimRight(p.baseURL, "/")
	}
	return defaultBaseURL
}

func (p *Provider) getHTTPClient() *http.Client {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.httpClient == nil {
		p.httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return p.httpClient
}

// lockZone serializes write operations on the same zone so that the provider
// is safe for concurrent use; it returns the unlock function.
func (p *Provider) lockZone(zone string) func() {
	key := strings.ToLower(strings.TrimSuffix(zone, "."))
	p.mu.Lock()
	if p.zoneLocks == nil {
		p.zoneLocks = make(map[string]*sync.Mutex)
	}
	l, ok := p.zoneLocks[key]
	if !ok {
		l = &sync.Mutex{}
		p.zoneLocks[key] = l
	}
	p.mu.Unlock()
	l.Lock()
	return l.Unlock
}

// getZoneID resolves a zone name to its Hostup zone ID, caching the result.
func (p *Provider) getZoneID(ctx context.Context, zone string) (string, error) {
	name := strings.TrimSuffix(zone, ".")
	key := strings.ToLower(name)

	p.mu.Lock()
	if p.zoneIDs == nil {
		p.zoneIDs = make(map[string]string)
	}
	id, ok := p.zoneIDs[key]
	p.mu.Unlock()
	if ok {
		return id, nil
	}

	zones, err := p.listZones(ctx, name)
	if err != nil {
		return "", err
	}
	for _, z := range zones {
		if strings.EqualFold(z.Name, name) {
			p.mu.Lock()
			p.zoneIDs[key] = z.ID
			p.mu.Unlock()
			return z.ID, nil
		}
	}
	if len(zones) == 1 {
		p.mu.Lock()
		p.zoneIDs[key] = zones[0].ID
		p.mu.Unlock()
		return zones[0].ID, nil
	}
	return "", fmt.Errorf("hostup: DNS zone %q not found on this account", zone)
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	apiRecs, err := p.listZoneRecords(ctx, zoneID)
	if err != nil {
		return nil, err
	}
	records := make([]libdns.Record, 0, len(apiRecs))
	for i := range apiRecs {
		records = append(records, apiRecs[i].toLibdnsRecord(zone))
	}
	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	unlock := p.lockZone(zone)
	defer unlock()

	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	appended := make([]libdns.Record, 0, len(records))
	for _, rec := range records {
		ap, err := toAPIRecord(zone, rec)
		if err != nil {
			return appended, err
		}
		created, err := p.createRecord(ctx, zoneID, ap)
		if err != nil {
			return appended, err
		}
		appended = append(appended, created.toLibdnsRecord(zone))
	}
	return appended, nil
}

// SetRecords sets the records in the zone, either by updating existing records
// or creating new ones, and deletes existing records of the same (name, type)
// pairs that are not part of the input. It returns the records that were set.
// The operation is not atomic: if it fails partway, some changes may remain.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	unlock := p.lockZone(zone)
	defer unlock()

	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	existing, err := p.listZoneRecords(ctx, zoneID)
	if err != nil {
		return nil, err
	}

	desired := make([]apiRecord, 0, len(records))
	for _, rec := range records {
		ap, err := toAPIRecord(zone, rec)
		if err != nil {
			return nil, err
		}
		desired = append(desired, ap)
	}

	matched := make([]bool, len(existing))
	set := make([]libdns.Record, 0, len(desired))
	for _, d := range desired {
		idx := -1
		for i := range existing {
			if !matched[i] && sameRecord(zone, d, existing[i]) {
				idx = i
				break
			}
		}
		var result *apiRecord
		if idx >= 0 {
			matched[idx] = true
			result, err = p.updateRecord(ctx, zoneID, existing[idx].ID, d)
		} else {
			result, err = p.createRecord(ctx, zoneID, d)
		}
		if err != nil {
			return set, err
		}
		set = append(set, result.toLibdnsRecord(zone))
	}

	for i := range existing {
		if matched[i] || !coveredByDesired(zone, existing[i], desired) {
			continue
		}
		if err := p.deleteRecord(ctx, zoneID, existing[i].ID); err != nil {
			return set, err
		}
	}
	return set, nil
}

// coveredByDesired reports whether an existing record's (name, type) pair is
// part of the desired records, meaning SetRecords must remove it.
func coveredByDesired(zone string, existing apiRecord, desired []apiRecord) bool {
	name := apiNameToRelative(existing.Name, zone)
	typ := strings.ToUpper(existing.Type)
	for _, d := range desired {
		if d.Name == name && strings.EqualFold(d.Type, typ) {
			return true
		}
	}
	return false
}

// DeleteRecords deletes the specified records from the zone. It returns the
// records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	unlock := p.lockZone(zone)
	defer unlock()

	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	existing, err := p.listZoneRecords(ctx, zoneID)
	if err != nil {
		return nil, err
	}

	deleted := []libdns.Record{}
	consumed := make([]bool, len(existing))
	for _, rec := range records {
		m, err := newRecordMatcher(zone, rec)
		if err != nil {
			return deleted, err
		}
		for i := range existing {
			if consumed[i] || !m.matches(zone, existing[i]) {
				continue
			}
			consumed[i] = true
			if err := p.deleteRecord(ctx, zoneID, existing[i].ID); err != nil {
				return deleted, err
			}
			deleted = append(deleted, existing[i].toLibdnsRecord(zone))
		}
	}
	return deleted, nil
}

// ListZones returns the list of available DNS zones.
func (p *Provider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	apiZones, err := p.listZones(ctx, "")
	if err != nil {
		return nil, err
	}
	zones := make([]libdns.Zone, 0, len(apiZones))
	for _, z := range apiZones {
		name := z.Name
		if !strings.HasSuffix(name, ".") {
			name += "."
		}
		zones = append(zones, libdns.Zone{Name: name})
	}
	return zones, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
	_ libdns.ZoneLister     = (*Provider)(nil)
)
