//go:build oracle

// Development-time correctness check for pkg/parser/nsc, which exists
// specifically because androidbinary.XMLFile cannot read CDATA (see that
// package's doc comment) — the domain names in a network_security_config
// are otherwise invisible. `aapt2 dump xmltree` is an independent,
// from-scratch decoder that does print CDATA (as "T: 'text'" lines), so
// it can verify domain names as well as element/attribute structure —
// unlike the manifest/DEX/ARSC oracles, which only had counts or
// resolved fields to compare, this is the first oracle that can check
// this package's whole reason for existing.
//
// Requires an APK in the corpus with an actual <domain-config> block —
// most of the current corpus's network_security_config files are
// base-config-only (see MG-002's rule doc). MOBILEGATE_ORACLE_APK/
// MOBILEGATE_ORACLE_MULTIDEX_APK are reused only if they happen to carry
// one; MOBILEGATE_ORACLE_NSC_APK lets `make oracle` point this
// specifically at one that does (Tusky, in the batch-1 corpus).
//
// Same rules as the other oracles: oracle-tagged, never ships, never
// runs in plain `go test ./...`, skips cleanly if aapt2 isn't found.
package oracle

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/prasadnadkarni/mobilegate/pkg/parser/apk"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/manifest"
	"github.com/prasadnadkarni/mobilegate/pkg/parser/nsc"
)

func TestNetworkSecurityConfigAgainstAapt2(t *testing.T) {
	apkPath := os.Getenv("MOBILEGATE_ORACLE_NSC_APK")
	if apkPath == "" {
		t.Skip("MOBILEGATE_ORACLE_NSC_APK not set; run via `make oracle` — see tools/oracle/README.md")
	}
	aapt2Path, err := findTool("aapt2")
	if err != nil {
		t.Skipf("aapt2 not available: %v (install Android SDK build-tools, or set ANDROID_HOME)", err)
	}

	container, err := apk.Open(apkPath)
	if err != nil {
		t.Fatalf("apk.Open: %v", err)
	}
	defer container.Close()

	m, err := manifest.Parse(container.Manifest, container.ResourcesArsc)
	if err != nil {
		t.Fatalf("manifest.Parse: %v", err)
	}
	if m.NetworkSecurityConfig == "" {
		t.Skipf("%s has no android:networkSecurityConfig — nothing to check", apkPath)
	}

	nscData, found, err := container.ReadFile(m.NetworkSecurityConfig)
	if err != nil {
		t.Fatalf("container.ReadFile(%s): %v", m.NetworkSecurityConfig, err)
	}
	if !found {
		t.Fatalf("resolved network_security_config path %s not found in APK", m.NetworkSecurityConfig)
	}

	ours, err := nsc.Parse(nscData)
	if err != nil {
		t.Fatalf("nsc.Parse: %v", err)
	}

	out, err := exec.Command(aapt2Path, "dump", "xmltree", apkPath, "--file", m.NetworkSecurityConfig).Output()
	if err != nil {
		t.Fatalf("aapt2 dump xmltree: %v", err)
	}
	theirs, err := parseAapt2XMLTreeNSC(out)
	if err != nil {
		t.Fatalf("parsing aapt2 xmltree output: %v", err)
	}

	t.Logf("%s (%s): ours=%d configs, aapt2=%d configs", apkPath, m.NetworkSecurityConfig, len(ours), len(theirs))

	if len(ours) != len(theirs) {
		t.Fatalf("config count mismatch: ours=%d aapt2=%d\nours=%+v\ntheirs=%+v", len(ours), len(theirs), ours, theirs)
	}
	for i := range ours {
		o, a := summarize(ours[i].Kind, ours[i].CleartextPermitted, ours[i].Domains), theirs[i]
		if o != a {
			t.Errorf("config[%d] mismatch:\n  ours:  %s\n  aapt2: %s", i, o, a)
		}
	}
}

type oracleDomain struct {
	name              string
	includeSubdomains bool
}

func summarize(kind nsc.ConfigKind, cleartext manifest.Tristate, domains []nsc.Domain) string {
	ct := "unset"
	switch cleartext {
	case manifest.True:
		ct = "true"
	case manifest.False:
		ct = "false"
	}
	names := make([]string, len(domains))
	for i, d := range domains {
		names[i] = fmt.Sprintf("%s(subdomains=%v)", d.Name, d.IncludeSubdomains)
	}
	sort.Strings(names)
	return fmt.Sprintf("%s cleartext=%s domains=%v", kind, ct, names)
}

var (
	reElement = regexp.MustCompile(`^(\s*)E: (\S+)`)
	reAttr    = regexp.MustCompile(`^\s*A: (\S+?)=(\S+)`)
	reCData   = regexp.MustCompile(`^\s*T: '(.*)'$`)
)

// parseAapt2XMLTreeNSC walks aapt2 dump xmltree's indented text output
// (indentation is not a fixed step per depth, so nesting is tracked by
// comparing each line's leading-space count against a stack, not by
// assuming a fixed width) and extracts the same summary shape nsc.Parse
// produces, for domain-config/base-config elements only.
func parseAapt2XMLTreeNSC(out []byte) ([]string, error) {
	type elemFrame struct {
		indent int
		name   string
		cfg    *configFrame // enclosing domain-config/base-config, or nil
		domain *oracleDomain
	}
	var elemStack []elemFrame
	var configs []*configFrame

	closeFrame := func(f elemFrame) {
		if f.name == "domain" && f.domain != nil && f.cfg != nil {
			f.cfg.domains = append(f.cfg.domains, *f.domain)
		}
	}

	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	for sc.Scan() {
		line := sc.Text()

		if m := reElement.FindStringSubmatch(line); m != nil {
			indent := len(m[1])
			name := m[2]
			for len(elemStack) > 0 && elemStack[len(elemStack)-1].indent >= indent {
				closeFrame(elemStack[len(elemStack)-1])
				elemStack = elemStack[:len(elemStack)-1]
			}
			var cfg *configFrame
			if len(elemStack) > 0 {
				cfg = elemStack[len(elemStack)-1].cfg
			}
			var domain *oracleDomain
			switch name {
			case "domain-config", "base-config":
				cfg = &configFrame{kind: name, cleartext: "unset"}
				configs = append(configs, cfg)
			case "domain":
				domain = &oracleDomain{}
			}
			elemStack = append(elemStack, elemFrame{indent: indent, name: name, cfg: cfg, domain: domain})
			continue
		}

		if m := reAttr.FindStringSubmatch(line); m != nil {
			if len(elemStack) == 0 {
				continue
			}
			top := &elemStack[len(elemStack)-1]
			attrName, val := m[1], strings.Trim(m[2], `"`)
			switch {
			case attrName == "cleartextTrafficPermitted" && top.cfg != nil && (top.name == "domain-config" || top.name == "base-config"):
				top.cfg.cleartext = val
			case attrName == "includeSubdomains" && top.domain != nil:
				top.domain.includeSubdomains = val == "true"
			}
			continue
		}

		if m := reCData.FindStringSubmatch(line); m != nil {
			if len(elemStack) > 0 && elemStack[len(elemStack)-1].domain != nil {
				elemStack[len(elemStack)-1].domain.name = m[1]
			}
			continue
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	for len(elemStack) > 0 {
		closeFrame(elemStack[len(elemStack)-1])
		elemStack = elemStack[:len(elemStack)-1]
	}

	summaries := make([]string, len(configs))
	for i, cf := range configs {
		names := make([]string, len(cf.domains))
		for j, d := range cf.domains {
			names[j] = fmt.Sprintf("%s(subdomains=%v)", d.name, d.includeSubdomains)
		}
		sort.Strings(names)
		summaries[i] = fmt.Sprintf("%s cleartext=%s domains=%v", cf.kind, cf.cleartext, names)
	}
	return summaries, nil
}

type configFrame struct {
	kind      string
	cleartext string
	domains   []oracleDomain
}
