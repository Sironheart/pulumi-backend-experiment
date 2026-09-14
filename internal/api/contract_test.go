//go:build contract

package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type recordedRequest struct {
	Method        string
	Path          string
	Authorization string
}

type requestRecorder struct {
	next http.Handler
	mu   sync.Mutex
	seen []recordedRequest
}

func (r *requestRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.seen = append(r.seen, recordedRequest{
		Method: req.Method, Path: req.URL.Path, Authorization: req.Header.Get("Authorization"),
	})
	r.mu.Unlock()
	r.next.ServeHTTP(w, req)
}

func TestPulumiCLIContract(t *testing.T) {
	if _, err := exec.LookPath("pulumi"); err != nil {
		t.Skip("pulumi CLI is not on PATH")
	}

	h := newNoAuthHarness(t)
	recorder := &requestRecorder{next: h.server}
	server := httptest.NewServer(recorder)
	t.Cleanup(server.Close)

	workdir := copyContractFixture(t)
	t.Setenv("PULUMI_HOME", t.TempDir())
	t.Setenv("PULUMI_SKIP_UPDATE_CHECK", "true")
	t.Setenv("PULUMI_CONFIG_PASSPHRASE", "contract-test-passphrase")
	// Avoid the CLI's automatic AI-agent signup path when this test runs under
	// an agent harness; noAuth accepts this isolated test token.
	t.Setenv("PULUMI_ACCESS_TOKEN", "contract-test-token")

	runPulumi(t, workdir, "login", "--non-interactive", server.URL)
	runPulumi(t, workdir, "stack", "init", "acme/pulumi-backend-contract/dev", "--non-interactive")
	runPulumi(t, workdir, "stack", "export", "--file", "fresh-stack.json")
	runPulumi(t, workdir, "up", "--yes", "--skip-preview", "--non-interactive")
	runPulumi(t, workdir, "preview", "--non-interactive")

	assertCLIWireContract(t, recorder.seen)
}

func copyContractFixture(t *testing.T) string {
	t.Helper()
	source := filepath.Join("testdata", "pulumi-contract")
	destination := t.TempDir()
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		contents, err := os.ReadFile(filepath.Join(source, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(destination, entry.Name()), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return destination
}

func runPulumi(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "pulumi", args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("pulumi %s: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func assertCLIWireContract(t *testing.T, requests []recordedRequest) {
	t.Helper()
	var sawCheckpoint, sawUpdateToken bool
	for _, request := range requests {
		if strings.Contains(request.Path, "/journalentries") || strings.Contains(request.Path, "checkpointdelta") {
			t.Fatalf("unsupported journal or delta route called: %s %s", request.Method, request.Path)
		}
		if strings.HasSuffix(request.Path, "/checkpoint") || strings.HasSuffix(request.Path, "/checkpointverbatim") {
			sawCheckpoint = true
			if strings.HasPrefix(request.Authorization, "update-token ") {
				sawUpdateToken = true
			}
		}
	}
	if !sawCheckpoint {
		t.Fatal("CLI did not send a full checkpoint")
	}
	if !sawUpdateToken {
		t.Fatal("checkpoint request did not use an update-token")
	}
}
