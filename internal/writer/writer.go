// Package writer provides atomic certificate material persistence to disk.
package writer

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	certmaid "github.com/helixzz/certmaid"
)

// FileWriter persists certificate bundles to disk using atomic write+rename.
type FileWriter struct {
	BaseDir string
}

// NewFileWriter creates a new FileWriter rooted at baseDir.
func NewFileWriter(baseDir string) *FileWriter {
	return &FileWriter{BaseDir: baseDir}
}

// Write persists a certificate bundle to disk. If output contains custom paths
// they are used directly. Otherwise the archive/live directory structure is used
// under BaseDir.
func (w *FileWriter) Write(name string, bundle *certmaid.CertificateBundle, output certmaid.OutputConfig) error {
	if output.CertPath != "" {
		return w.writeCustom(bundle, output)
	}
	return w.writeArchiveLive(name, bundle)
}

// writeCustom writes certificate material to explicitly configured paths.
func (w *FileWriter) writeCustom(bundle *certmaid.CertificateBundle, output certmaid.OutputConfig) error {
	if err := atomicWrite(output.CertPath, bundle.Certificate, 0644); err != nil {
		return fmt.Errorf("cert path: %w", err)
	}
	if err := atomicWrite(output.KeyPath, bundle.PrivateKey, 0600); err != nil {
		return fmt.Errorf("key path: %w", err)
	}
	if output.ChainPath != "" {
		chain := buildChain(bundle)
		if err := atomicWrite(output.ChainPath, chain, 0644); err != nil {
			return fmt.Errorf("chain path: %w", err)
		}
	}
	return nil
}

// writeArchiveLive writes certificate material using the archive/live structure.
func (w *FileWriter) writeArchiveLive(name string, bundle *certmaid.CertificateBundle) error {
	timestamp := time.Now().Format("20060102")

	archiveDir := filepath.Join(w.BaseDir, "archive", name)
	liveDir := filepath.Join(w.BaseDir, "live", name)

	certFile := fmt.Sprintf("cert-%s.pem", timestamp)
	keyFile := fmt.Sprintf("key-%s.pem", timestamp)
	chainFile := fmt.Sprintf("chain-%s.pem", timestamp)

	certPath := filepath.Join(archiveDir, certFile)
	keyPath := filepath.Join(archiveDir, keyFile)
	chainPath := filepath.Join(archiveDir, chainFile)

	// Write archive files atomically.
	if err := atomicWrite(certPath, bundle.Certificate, 0644); err != nil {
		return fmt.Errorf("archive cert: %w", err)
	}
	if err := atomicWrite(keyPath, bundle.PrivateKey, 0600); err != nil {
		return fmt.Errorf("archive key: %w", err)
	}

	chain := buildChain(bundle)
	if err := atomicWrite(chainPath, chain, 0644); err != nil {
		return fmt.Errorf("archive chain: %w", err)
	}

	// Create/update live symlinks atomically.
	if err := atomicSymlink(certPath, filepath.Join(liveDir, "cert.pem")); err != nil {
		return fmt.Errorf("live cert symlink: %w", err)
	}
	if err := atomicSymlink(keyPath, filepath.Join(liveDir, "key.pem")); err != nil {
		return fmt.Errorf("live key symlink: %w", err)
	}
	if err := atomicSymlink(chainPath, filepath.Join(liveDir, "chain.pem")); err != nil {
		return fmt.Errorf("live chain symlink: %w", err)
	}

	return nil
}

// buildChain concatenates IssuingCA and all CAChain certificates into a single
// PEM block sequence.
func buildChain(bundle *certmaid.CertificateBundle) []byte {
	var buf bytes.Buffer
	buf.Write(bundle.IssuingCA)
	for _, ca := range bundle.CAChain {
		buf.WriteByte('\n')
		buf.Write(ca)
	}
	return buf.Bytes()
}

// atomicWrite writes data to path atomically using temp file + rename.
// The file is fsync'd and chmod'd before the rename.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".certmaid-write-*")
	if err != nil {
		return fmt.Errorf("createtemp: %w", err)
	}
	tmpPath := f.Name()

	// Clean up temp file on failure.
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmpPath)
		}
	}()

	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write: %w", err)
	}

	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("fsync: %w", err)
	}

	if err := f.Chmod(perm); err != nil {
		f.Close()
		return fmt.Errorf("chmod: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}

	ok = true
	return nil
}

// atomicSymlink creates a symlink at linkPath pointing to target atomically
// by creating a temp symlink and renaming it into place.
func atomicSymlink(target, linkPath string) error {
	if err := os.MkdirAll(filepath.Dir(linkPath), 0750); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	dir := filepath.Dir(linkPath)
	tmpPath := filepath.Join(dir, ".certmaid-symlink-"+randomSuffix())

	if err := os.Symlink(target, tmpPath); err != nil {
		return fmt.Errorf("symlink: %w", err)
	}

	// Clean up temp symlink on failure.
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmpPath)
		}
	}()

	if err := os.Rename(tmpPath, linkPath); err != nil {
		return fmt.Errorf("rename: %w", err)
	}

	ok = true
	return nil
}

// randomSuffix returns a short random suffix for temp file names.
// Using a time-based approach avoids importing crypto/rand or math/rand
// while still providing uniqueness within a single process.
var suffixCounter int

func randomSuffix() string {
	suffixCounter++
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), suffixCounter)
}
