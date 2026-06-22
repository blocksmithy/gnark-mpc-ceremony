package ceremony

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Storage persists the live ceremony state (head + transcript) and archives each
// accepted contribution. M1 ships a local-disk implementation; production swaps
// an S3-compatible hot path + IPFS archive behind the same interface (the
// returned blob ref becomes an IPFS CID).
type Storage interface {
	SaveHead(b Blob) error
	LoadHead(b Blob) error // reads into the caller-provided empty blob
	SaveBlob(index int, b Blob) (ref string, err error)
	LoadChain(backend Backend) ([]Blob, error) // ordered accepted Phase-2 contributions
	SaveTranscript(t *Transcript) error
	LoadTranscript() (*Transcript, error)
}

// LocalStorage is a directory: head.bin, transcript.json, blobs/NNNNN-<sha8>.bin.
type LocalStorage struct{ dir string }

func NewLocalStorage(dir string) (*LocalStorage, error) {
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o755); err != nil {
		return nil, err
	}
	return &LocalStorage{dir: dir}, nil
}

func writeBlobFile(path string, b Blob) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err := b.WriteTo(f); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (s *LocalStorage) SaveHead(b Blob) error {
	return writeBlobFile(filepath.Join(s.dir, "head.bin"), b)
}

func (s *LocalStorage) LoadHead(b Blob) error {
	f, err := os.Open(filepath.Join(s.dir, "head.bin"))
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = b.ReadFrom(f)
	return err
}

func (s *LocalStorage) SaveBlob(index int, b Blob) (string, error) {
	h, err := HashBlob(b)
	if err != nil {
		return "", err
	}
	name := fmt.Sprintf("%05d-%s.bin", index, hex.EncodeToString(h[:4]))
	if err := writeBlobFile(filepath.Join(s.dir, "blobs", name), b); err != nil {
		return "", err
	}
	return name, nil
}

func (s *LocalStorage) LoadChain(backend Backend) ([]Blob, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, "blobs"))
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // NNNNN- prefix -> contribution order
	chain := make([]Blob, 0, len(names))
	for _, name := range names {
		f, err := os.Open(filepath.Join(s.dir, "blobs", name))
		if err != nil {
			return nil, err
		}
		b := backend.NewPhase2()
		_, err = b.ReadFrom(f)
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		chain = append(chain, b)
	}
	return chain, nil
}

func (s *LocalStorage) SaveTranscript(t *Transcript) error {
	b, err := t.snapshot()
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, "transcript.json"), b, 0o644)
}

func (s *LocalStorage) LoadTranscript() (*Transcript, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, "transcript.json"))
	if err != nil {
		return nil, err
	}
	return LoadTranscriptJSON(b)
}

// sha256Hex is a small helper for refs/fingerprints.
func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
