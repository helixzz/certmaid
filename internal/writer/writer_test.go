package writer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	certmaid "github.com/helixzz/certmaid"
)

func TestWrite_ArchiveLive(t *testing.T) {
	dir := t.TempDir()
	w := NewFileWriter(dir)

	cert := []byte("-----BEGIN CERTIFICATE-----\ncert-data\n-----END CERTIFICATE-----")
	key := []byte("-----BEGIN PRIVATE KEY-----\nkey-data\n-----END PRIVATE KEY-----")
	issuingCA := []byte("-----BEGIN CERTIFICATE-----\nissuing-ca\n-----END CERTIFICATE-----")
	caChain := [][]byte{
		[]byte("-----BEGIN CERTIFICATE-----\nintermediate\n-----END CERTIFICATE-----"),
	}

	bundle := &certmaid.CertificateBundle{
		Certificate: cert,
		PrivateKey:  key,
		IssuingCA:   issuingCA,
		CAChain:     caChain,
		Domains:     []string{"example.com"},
		NotAfter:    time.Now().Add(90 * 24 * time.Hour),
	}

	err := w.Write("example.com", bundle, certmaid.OutputConfig{})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	timestamp := time.Now().Format("20060102")

	// Check archive files exist with correct content.
	archiveDir := filepath.Join(dir, "archive", "example.com")
	checkFile(t, filepath.Join(archiveDir, "cert-"+timestamp+".pem"), cert, 0644)
	checkFile(t, filepath.Join(archiveDir, "key-"+timestamp+".pem"), key, 0600)

	expectedChain := string(issuingCA) + "\n" + string(caChain[0])
	checkFile(t, filepath.Join(archiveDir, "chain-"+timestamp+".pem"), []byte(expectedChain), 0644)

	// Check live symlinks point to correct archive files.
	liveDir := filepath.Join(dir, "live", "example.com")
	certTarget := filepath.Join(archiveDir, "cert-"+timestamp+".pem")
	keyTarget := filepath.Join(archiveDir, "key-"+timestamp+".pem")
	chainTarget := filepath.Join(archiveDir, "chain-"+timestamp+".pem")

	checkSymlink(t, filepath.Join(liveDir, "cert.pem"), certTarget)
	checkSymlink(t, filepath.Join(liveDir, "key.pem"), keyTarget)
	checkSymlink(t, filepath.Join(liveDir, "chain.pem"), chainTarget)
}

func TestWrite_CustomPaths(t *testing.T) {
	dir := t.TempDir()
	w := NewFileWriter(dir)

	cert := []byte("-----BEGIN CERTIFICATE-----\ncustom-cert\n-----END CERTIFICATE-----")
	key := []byte("-----BEGIN PRIVATE KEY-----\ncustom-key\n-----END PRIVATE KEY-----")
	issuingCA := []byte("-----BEGIN CERTIFICATE-----\ncustom-issuer\n-----END CERTIFICATE-----")

	bundle := &certmaid.CertificateBundle{
		Certificate: cert,
		PrivateKey:  key,
		IssuingCA:   issuingCA,
		NotAfter:    time.Now().Add(90 * 24 * time.Hour),
	}

	certPath := filepath.Join(dir, "custom", "server.crt")
	keyPath := filepath.Join(dir, "custom", "server.key")
	chainPath := filepath.Join(dir, "custom", "ca-bundle.crt")

	err := w.Write("example.com", bundle, certmaid.OutputConfig{
		CertPath:  certPath,
		KeyPath:   keyPath,
		ChainPath: chainPath,
	})
	if err != nil {
		t.Fatalf("Write() custom paths error = %v", err)
	}

	checkFile(t, certPath, cert, 0644)
	checkFile(t, keyPath, key, 0600)
	checkFile(t, chainPath, issuingCA, 0644)
}

func TestWrite_CustomPaths_NoArchive(t *testing.T) {
	dir := t.TempDir()
	w := NewFileWriter(dir)

	bundle := &certmaid.CertificateBundle{
		Certificate: []byte("cert"),
		PrivateKey:  []byte("key"),
		IssuingCA:   []byte("chain"),
	}

	certPath := filepath.Join(dir, "direct", "cert.pem")
	keyPath := filepath.Join(dir, "direct", "key.pem")

	err := w.Write("test", bundle, certmaid.OutputConfig{
		CertPath: certPath,
		KeyPath:  keyPath,
	})
	if err != nil {
		t.Fatalf("Write() custom no-chain error = %v", err)
	}

	// Archive dir should not exist when custom paths are used.
	if _, err := os.Stat(filepath.Join(dir, "archive")); !os.IsNotExist(err) {
		t.Error("archive directory should not be created when custom paths are used")
	}
	if _, err := os.Stat(filepath.Join(dir, "live")); !os.IsNotExist(err) {
		t.Error("live directory should not be created when custom paths are used")
	}
}

func TestWrite_DirectoryCreation(t *testing.T) {
	dir := t.TempDir()
	w := NewFileWriter(dir)

	bundle := &certmaid.CertificateBundle{
		Certificate: []byte("cert"),
		PrivateKey:  []byte("key"),
		IssuingCA:   []byte("chain"),
	}

	// Use deep nested custom path that doesn't exist yet.
	deepPath := filepath.Join(dir, "a", "b", "c", "output.crt")
	keyPath := filepath.Join(dir, "a", "b", "c", "output.key")

	err := w.Write("deep", bundle, certmaid.OutputConfig{
		CertPath: deepPath,
		KeyPath:  keyPath,
	})
	if err != nil {
		t.Fatalf("Write() deep dir error = %v", err)
	}

	checkFile(t, deepPath, []byte("cert"), 0644)
	checkFile(t, keyPath, []byte("key"), 0600)
}

func TestWrite_ArchiveLiveDirsCreated(t *testing.T) {
	dir := t.TempDir()
	// Point to a subdirectory that doesn't exist yet.
	w := NewFileWriter(filepath.Join(dir, "nonexistent"))

	bundle := &certmaid.CertificateBundle{
		Certificate: []byte("cert"),
		PrivateKey:  []byte("key"),
		IssuingCA:   []byte("chain"),
		NotAfter:    time.Now().Add(90 * 24 * time.Hour),
	}

	err := w.Write("test.example", bundle, certmaid.OutputConfig{})
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	// Verify directories were created with correct permissions.
	archiveDir := filepath.Join(dir, "nonexistent", "archive", "test.example")
	liveDir := filepath.Join(dir, "nonexistent", "live", "test.example")

	checkDirPerm(t, archiveDir, 0750)
	checkDirPerm(t, liveDir, 0750)
}

func TestBuildChain(t *testing.T) {
	bundle := &certmaid.CertificateBundle{
		IssuingCA: []byte("ISSUER"),
		CAChain: [][]byte{
			[]byte("INTERMEDIATE"),
			[]byte("ROOT"),
		},
	}

	got := buildChain(bundle)
	want := "ISSUER\nINTERMEDIATE\nROOT"

	if string(got) != want {
		t.Errorf("buildChain() = %q, want %q", string(got), want)
	}
}

func TestBuildChain_NoChain(t *testing.T) {
	bundle := &certmaid.CertificateBundle{
		IssuingCA: []byte("ISSUER"),
	}

	got := buildChain(bundle)

	if string(got) != "ISSUER" {
		t.Errorf("buildChain() = %q, want %q", string(got), "ISSUER")
	}
}

// Helpers

func checkFile(t *testing.T, path string, wantContent []byte, wantPerm os.FileMode) {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}

	if string(data) != string(wantContent) {
		// Show first differing line for readable output.
		t.Errorf("%s content mismatch\n  got:  %q\n  want: %q", path, string(data), string(wantContent))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s): %v", path, err)
	}

	if info.Mode().Perm() != wantPerm {
		t.Errorf("%s permissions = %v, want %v", path, info.Mode().Perm(), wantPerm)
	}
}

func checkSymlink(t *testing.T, linkPath string, wantTarget string) {
	t.Helper()

	target, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("Readlink(%s): %v", linkPath, err)
	}

	// Normalize for comparison — Readlink returns the raw path stored in the symlink.
	if !strings.HasSuffix(target, wantTarget) && target != wantTarget {
		t.Errorf("symlink %s -> %q, want -> %q", linkPath, target, wantTarget)
	}
}

func checkDirPerm(t *testing.T, dir string, want os.FileMode) {
	t.Helper()

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat(%s): %v", dir, err)
	}

	if info.Mode().Perm() != want {
		t.Errorf("dir %s permissions = %v, want %v", dir, info.Mode().Perm(), want)
	}
}
