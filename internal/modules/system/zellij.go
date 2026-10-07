package system

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// zellij is not packaged in Debian 12 / Ubuntu 24.04: it is installed from
// the official GitHub release, verified against the published sha256.
const (
	zellijBin = "/usr/local/bin/zellij"
	zellijURL = "https://github.com/zellij-org/zellij/releases/latest/download/"
)

// httpGet downloads a URL (replaced in tests).
var httpGet = func(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 200<<20))
}

func zellijArch() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64", nil
	case "arm64":
		return "aarch64", nil
	}
	return "", fmt.Errorf("no zellij build for %s", runtime.GOARCH)
}

// downloadZellij returns the verified zellij binary.
func downloadZellij(ctx context.Context) ([]byte, error) {
	arch, err := zellijArch()
	if err != nil {
		return nil, err
	}
	base := zellijURL + "zellij-" + arch + "-unknown-linux-musl"
	sumFile, err := httpGet(ctx, base+".sha256sum")
	if err != nil {
		return nil, err
	}
	f := strings.Fields(string(sumFile))
	if len(f) == 0 || len(f[0]) != 64 {
		return nil, errors.New("zellij: malformed sha256sum file")
	}
	tgz, err := httpGet(ctx, base+".tar.gz")
	if err != nil {
		return nil, err
	}
	bin, err := extract(tgz, "zellij")
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(bin)
	if hex.EncodeToString(sum[:]) != strings.ToLower(f[0]) {
		return nil, errors.New("zellij: sha256 mismatch, not installed")
	}
	return bin, nil
}

func extract(tgz []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("%s not found in the archive", name)
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag == tar.TypeReg && (h.Name == name || strings.HasSuffix(h.Name, "/"+name)) {
			return io.ReadAll(io.LimitReader(tr, 200<<20))
		}
	}
}
