package openfga

import (
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/openfga/language/pkg/go/transformer"

	"github.com/alexluong/platform-spike/go/internal/perm"
)

var update = flag.Bool("update", false, "rewrite model.fga from Model()")

// The committed model.fga is what `fga model test` checks; it must match the generator.
func TestModelFileUpToDate(t *testing.T) {
	got := Model()
	if *update {
		if err := os.WriteFile("model.fga", []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile("model.fga")
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Fatal("model.fga is stale: run go test ./internal/adapters/openfga -run TestModelFileUpToDate -update")
	}
}

// The DSL parses and every catalog action the executor can ask about is a relation on its scope type.
func TestEveryActionHasARelation(t *testing.T) {
	m, err := transformer.TransformDSLToProto(Model())
	if err != nil {
		t.Fatal(err)
	}
	rels := map[string]map[string]bool{}
	for _, td := range m.GetTypeDefinitions() {
		rels[td.GetType()] = map[string]bool{}
		for r := range td.GetRelations() {
			rels[td.GetType()][r] = true
		}
	}
	for _, a := range perm.Catalog {
		for _, sc := range []perm.ScopeType{perm.ScopePlatform, perm.ScopeMerchant, perm.ScopeStore} {
			if a.CheckableAt(sc) && !rels[string(sc)][Rel(a.ID)] {
				t.Errorf("%s: no relation %s on %s", a.ID, Rel(a.ID), sc)
			}
		}
	}
}

// fga model test runs the assertions in model.fga.yaml (custom roles, refund
// limit condition, agent grants under not_expired, apps, suspension, break-glass).
// Needs the fga CLI (go install github.com/openfga/cli/cmd/fga@latest); the
// stack b Docker build runs it too.
func TestFGAModelTest(t *testing.T) {
	fga, err := exec.LookPath("fga")
	if err != nil {
		t.Skip("fga not installed")
	}
	out, err := exec.Command(fga, "model", "test", "--tests", "model.fga.yaml").CombinedOutput()
	if err != nil || strings.Contains(string(out), "FAILING") {
		t.Fatalf("fga model test failed: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}

// The SDK request built from the DSL keeps every rewrite (a dropped oneof key
// would leave a relation with an empty definition, which the server rejects).
func TestModelRequestKeepsRewrites(t *testing.T) {
	req, err := modelRequest()
	if err != nil {
		t.Fatal(err)
	}
	for _, td := range req.TypeDefinitions {
		for name, us := range td.GetRelations() {
			if us.This == nil && us.ComputedUserset == nil && us.TupleToUserset == nil && us.Union == nil && us.Intersection == nil && us.Difference == nil {
				t.Errorf("%s#%s: empty rewrite", td.Type, name)
			}
		}
	}
	if len(req.GetConditions()) != 2 {
		t.Errorf("conditions: %v", req.GetConditions())
	}
}
