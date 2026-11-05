Hostup for [`libdns`](https://github.com/libdns/libdns)
=======================

[![Go Reference](https://pkg.go.dev/badge/github.com/libdns/hostup.svg)](https://pkg.go.dev/github.com/libdns/hostup)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for [Hostup](https://hostup.se) (hostup.se), allowing you to manage DNS records through the public [Hostup API v2](https://developer.hostup.se/).

## Configuring

Create an API key in the Hostup dashboard (under **API keys**) with the `read:dns` and `write:dns` scopes, then configure the provider with it:

```go
provider := hostup.Provider{
	APIToken: os.Getenv("HOSTUP_API_KEY"),
}
```

When used with Caddy, set the `HOSTUP_API_KEY` environment variable and configure `dns hostup` in the TLS automation policy.

## Example

```go
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/libdns/hostup"
	"github.com/libdns/libdns"
)

func main() {
	provider := hostup.Provider{APIToken: os.Getenv("HOSTUP_API_KEY")}
	ctx := context.Background()
	zone := "example.com."

	records, err := provider.GetRecords(ctx, zone)
	if err != nil {
		panic(err)
	}
	for _, rec := range records {
		fmt.Println(rec.RR())
	}

	set, err := provider.SetRecords(ctx, zone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "challenge-token", TTL: 120 * time.Second},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(set)
}
```

## Caveats

- Zones are addressed by their domain name (e.g. `"example.com."`) and resolved to the API's internal zone ID (`zone_...`) on first use; the mapping is cached.
- Record types `A`, `AAAA`, `CNAME`, `MX`, `NS`, `SRV`, `TXT` and `CAA` are returned as the corresponding libdns structs; `ALIAS`, `TLSA`, `SOA` and other types unknown to libdns are returned as `libdns.RR` values.
- Hostup accepts TTLs between 60 and 86400 seconds; a zero TTL is sent as the API default (3600 seconds).
- The CDN proxy state (`proxied`) of `A`, `AAAA` and `CNAME` records is not managed by this package.
