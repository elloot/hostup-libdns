package hostup

import (
	"fmt"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// defaultTTLSeconds is the TTL Hostup applies when a record is created or
// updated without an explicit TTL.
const defaultTTLSeconds = 3600

// apiZone represents a DNS zone in the Hostup API v2.
type apiZone struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status,omitempty"`
	IsDNSOnly   bool   `json:"isDnsOnly,omitempty"`
	Kind        string `json:"kind,omitempty"`
	RecordCount int    `json:"recordCount,omitempty"`
}

// listZonesResponse is the response body of GET /api/v2/dns-zones.
type listZonesResponse struct {
	Data       []apiZone `json:"data"`
	HasMore    bool      `json:"hasMore"`
	NextCursor *string   `json:"nextCursor"`
}

// apiRecord represents a DNS record in the Hostup API v2. In responses, Name
// is a full name (e.g. "www.example.com"); in request bodies, it is relative
// to the zone (e.g. "www", or "@" for the zone root).
type apiRecord struct {
	ID       string  `json:"id,omitempty"`
	Type     string  `json:"type"`
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	TTL      uint32  `json:"ttl,omitempty"`
	Priority *uint16 `json:"priority,omitempty"`
	Weight   *uint16 `json:"weight,omitempty"`
	Port     *uint16 `json:"port,omitempty"`
}

// zoneRecordsResponse is the response body of GET /api/v2/dns-zones/{id}/records.
type zoneRecordsResponse struct {
	Zone    apiZone     `json:"zone"`
	Records []apiRecord `json:"records"`
}

// toLibdnsRecord converts an API record into a libdns record, using the
// type-specific structs defined by libdns whenever the record type is known.
func (r apiRecord) toLibdnsRecord(zone string) libdns.Record {
	rr := libdns.RR{
		Name: apiNameToRelative(r.Name, zone),
		TTL:  time.Duration(r.TTL) * time.Second,
		Type: strings.ToUpper(r.Type),
		Data: r.Value,
	}
	switch rr.Type {
	case "MX":
		rr.Data = fmt.Sprintf("%d %s", deref(r.Priority), r.Value)
	case "SRV":
		rr.Data = fmt.Sprintf("%d %d %d %s", deref(r.Priority), deref(r.Weight), deref(r.Port), r.Value)
	}
	rec, err := rr.Parse()
	if err != nil {
		return rr
	}
	return rec
}

// toAPIRecord converts a libdns record into an API record for create/update
// requests. The record name is normalized to a zone-relative name.
func toAPIRecord(zone string, rec libdns.Record) (apiRecord, error) {
	if rrRec, ok := rec.(libdns.RR); ok {
		if parsed, err := rrRec.Parse(); err == nil {
			rec = parsed
		}
	}
	rr := rec.RR()
	if rr.Name == "" {
		return apiRecord{}, fmt.Errorf("hostup: record has no name")
	}
	a := apiRecord{
		Type:  strings.ToUpper(rr.Type),
		Name:  libdnsNameToRelative(rr.Name, zone),
		Value: rr.Data,
		TTL:   uint32(rr.TTL / time.Second),
	}
	if a.TTL == 0 {
		a.TTL = defaultTTLSeconds
	}
	switch r := rec.(type) {
	case libdns.Address:
		if r.IP.IsValid() {
			if r.IP.Is4() {
				a.Type = "A"
			} else {
				a.Type = "AAAA"
			}
			a.Value = r.IP.String()
		} else {
			a.Value = ""
		}
	case libdns.CNAME:
		a.Type = "CNAME"
		a.Value = trimTrailingDot(r.Target)
	case libdns.MX:
		a.Type = "MX"
		a.Value = trimTrailingDot(r.Target)
		p := r.Preference
		a.Priority = &p
	case libdns.NS:
		a.Type = "NS"
		a.Value = trimTrailingDot(r.Target)
	case libdns.SRV:
		a.Type = "SRV"
		a.Value = trimTrailingDot(r.Target)
		pr, w, po := r.Priority, r.Weight, r.Port
		a.Priority, a.Weight, a.Port = &pr, &w, &po
	case libdns.TXT:
		a.Type = "TXT"
		a.Value = r.Text
	case libdns.CAA:
		a.Type = "CAA"
		a.Value = fmt.Sprintf("%d %s %q", r.Flags, r.Tag, r.Value)
	}
	return a, nil
}

// apiNameToRelative converts a full record name returned by the API into a
// zone-relative libdns record name.
func apiNameToRelative(name, zone string) string {
	return libdns.RelativeName(name, zone)
}

// libdnsNameToRelative normalizes a libdns record name (relative or absolute)
// into the zone-relative name the API expects in request bodies.
func libdnsNameToRelative(name, zone string) string {
	return libdns.RelativeName(libdns.AbsoluteName(name, zone), zone)
}

func trimTrailingDot(s string) string {
	return strings.TrimSuffix(s, ".")
}

// normalizeValue canonicalizes a record value for comparison; hostname
// targets are compared without their trailing dot.
func normalizeValue(recType, value string) string {
	switch strings.ToUpper(recType) {
	case "CNAME", "ALIAS", "MX", "NS", "SRV":
		return trimTrailingDot(value)
	default:
		return value
	}
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

func ptrEqual[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// sameRecord reports whether a desired API record and an existing API record
// describe the same DNS record (name, type, value and MX/SRV fields).
func sameRecord(zone string, desired, existing apiRecord) bool {
	return desired.Name == apiNameToRelative(existing.Name, zone) &&
		strings.EqualFold(desired.Type, existing.Type) &&
		normalizeValue(desired.Type, desired.Value) == normalizeValue(existing.Type, existing.Value) &&
		ptrEqual(desired.Priority, existing.Priority) &&
		ptrEqual(desired.Weight, existing.Weight) &&
		ptrEqual(desired.Port, existing.Port)
}

// recordMatcher matches existing zone records against an input record for
// DeleteRecords, honoring the libdns wildcard semantics: an empty type, TTL
// or value in the input matches any value of that field.
type recordMatcher struct {
	name       string
	typ        string
	value      string
	ttl        uint32
	priority   *uint16
	weight     *uint16
	port       *uint16
	matchType  bool
	matchValue bool
	matchTTL   bool
}

func newRecordMatcher(zone string, rec libdns.Record) (recordMatcher, error) {
	rr := rec.RR()
	ap, err := toAPIRecord(zone, rec)
	if err != nil {
		return recordMatcher{}, err
	}
	return recordMatcher{
		name:       ap.Name,
		typ:        ap.Type,
		value:      normalizeValue(ap.Type, ap.Value),
		ttl:        ap.TTL,
		priority:   ap.Priority,
		weight:     ap.Weight,
		port:       ap.Port,
		matchType:  rr.Type != "",
		matchValue: rr.Data != "",
		matchTTL:   rr.TTL != 0,
	}, nil
}

func (m recordMatcher) matches(zone string, existing apiRecord) bool {
	if apiNameToRelative(existing.Name, zone) != m.name {
		return false
	}
	typ := strings.ToUpper(existing.Type)
	if m.matchType && typ != m.typ {
		return false
	}
	if m.matchValue {
		if normalizeValue(typ, existing.Value) != m.value {
			return false
		}
		if !ptrEqual(m.priority, existing.Priority) ||
			!ptrEqual(m.weight, existing.Weight) ||
			!ptrEqual(m.port, existing.Port) {
			return false
		}
	}
	if m.matchTTL && existing.TTL != m.ttl {
		return false
	}
	return true
}
