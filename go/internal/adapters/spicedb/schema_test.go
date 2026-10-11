package spicedb

import (
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/alexluong/platform-spike/go/internal/perm"
)

var update = flag.Bool("update", false, "rewrite schema.zed from Schema()")

// The committed schema.zed is what zed validate checks; it must match the generator.
func TestSchemaFileUpToDate(t *testing.T) {
	got := Schema()
	if *update {
		if err := os.WriteFile("schema.zed", []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile("schema.zed")
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Fatal("schema.zed is stale: run go test ./internal/adapters/spicedb -run TestSchemaFileUpToDate -update")
	}
}

// Every catalog action the executor can ask about maps to a permission on its scope definitions.
func TestEveryActionHasAPermission(t *testing.T) {
	s := Schema()
	for _, a := range perm.Catalog {
		for _, sc := range []perm.ScopeType{perm.ScopePlatform, perm.ScopeMerchant, perm.ScopeStore} {
			if !a.CheckableAt(sc) {
				continue
			}
			def := s[strings.Index(s, "definition "+string(sc)+" {"):]
			def = def[:strings.Index(def, "\n}")]
			if !strings.Contains(def, "permission "+Perm(a.ID)+" =") {
				t.Errorf("%s: no permission %s on %s", a.ID, Perm(a.ID), sc)
			}
		}
	}
}

// zed validate runs the schema assertions in validation.yaml (custom roles,
// caveated refund limits, expiring agent grants, apps, suspension, break-glass).
// Needs the zed CLI (go install github.com/authzed/zed/cmd/zed@latest) or docker;
// the Docker build also runs it.
func TestZedValidate(t *testing.T) {
	zed, err := exec.LookPath("zed")
	if err != nil {
		t.Skip("zed not installed")
	}
	out, err := exec.Command(zed, "validate", "validation.yaml").CombinedOutput()
	if err != nil {
		t.Fatalf("zed validate failed: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}
