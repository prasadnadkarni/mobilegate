package engine

import (
	"testing"

	"github.com/prasadnadkarni/mobilegate/pkg/parser/nsc"
)

// TestFirstPartyMatch_Direction pins down the direction of the subdomain
// check specifically — the case this package's own first draft got
// backwards while writing it: <domain includeSubdomains="true">
// example.com</domain> covers api.example.com (a first-party subdomain
// of the entry), but a first-party domain of "example.com" is NOT
// covered by an entry of "api.example.com" (a more specific entry never
// broadens to cover a less specific parent domain).
func TestFirstPartyMatch_Direction(t *testing.T) {
	tests := []struct {
		name              string
		entryDomain       string
		includeSubdomains bool
		firstParty        []string
		wantMatch         bool
	}{
		{
			name:              "exact match, no subdomains needed",
			entryDomain:       "example.com",
			includeSubdomains: false,
			firstParty:        []string{"example.com"},
			wantMatch:         true,
		},
		{
			name:              "first-party subdomain covered when entry allows subdomains",
			entryDomain:       "example.com",
			includeSubdomains: true,
			firstParty:        []string{"api.example.com"},
			wantMatch:         true,
		},
		{
			name:              "first-party subdomain NOT covered when entry disallows subdomains",
			entryDomain:       "example.com",
			includeSubdomains: false,
			firstParty:        []string{"api.example.com"},
			wantMatch:         false,
		},
		{
			name:              "more specific entry does not broaden to cover a parent domain",
			entryDomain:       "api.example.com",
			includeSubdomains: true,
			firstParty:        []string{"example.com"},
			wantMatch:         false,
		},
		{
			name:              "unrelated domain never matches",
			entryDomain:       "example.com",
			includeSubdomains: true,
			firstParty:        []string{"totally-different.org"},
			wantMatch:         false,
		},
		{
			name:              "case-insensitive exact match",
			entryDomain:       "Example.COM",
			includeSubdomains: false,
			firstParty:        []string{"example.com"},
			wantMatch:         true,
		},
		{
			name:              "no configured first-party domains never matches",
			entryDomain:       "example.com",
			includeSubdomains: true,
			firstParty:        nil,
			wantMatch:         false,
		},
		{
			name:              "substring but not a subdomain does not match",
			entryDomain:       "example.com",
			includeSubdomains: true,
			firstParty:        []string{"notexample.com"},
			wantMatch:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := nsc.Domain{Name: tt.entryDomain, IncludeSubdomains: tt.includeSubdomains}
			_, got := firstPartyMatch(d, tt.firstParty)
			if got != tt.wantMatch {
				t.Errorf("firstPartyMatch(%+v, %v) = %v, want %v", d, tt.firstParty, got, tt.wantMatch)
			}
		})
	}
}
