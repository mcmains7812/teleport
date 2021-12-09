package x11

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/gravitational/trace"
)

const (
	xauthBinName   = "xauth"
	xauthPathEnv   = "XAUTHORITY"
	xauthHomePath  = ".Xauthority"
	xauthProto     = "MIT-MAGIC-COOKIE-1"
	xauthProtoSize = 16
)

func runXAuthCommand(ctx context.Context, xauthFile string, args ...string) ([]byte, error) {
	if xauthFile != "" {
		args = append([]string{"-f", xauthFile}, args...)
	}
	cmd := exec.CommandContext(ctx, "xauth", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return out, nil
}

// spoofXAuthEntry creates a copy of the given xAuthEntry with a new random cookie
func spoofXAuthEntry(entry *xAuthEntry) (*xAuthEntry, error) {
	return &xAuthEntry{
		display: entry.display,
		proto:   entry.proto,
		token:   "",
	}, nil

	// bytes := make([]byte, len)
	// if _, err := rand.Read(bytes); err != nil {
	// 	return "", trace.Wrap(err)
	// }
	// return hex.EncodeToString(bytes), nil
}

func generateUntrustedXAuthEntry(ctx context.Context, display string, ttl time.Duration) (*xAuthEntry, error) {
	xauthDir, err := os.MkdirTemp(os.TempDir(), "tsh-*")
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer os.RemoveAll(xauthDir)

	xauthFile, err := os.CreateTemp(xauthDir, "xauthfile")
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := generateXAuthEntry(ctx, xauthFile.Name(), display, xauthProto, false, ttl); err != nil {
		return nil, trace.Wrap(err)
	}

	xAuthEntry, err := readXAuthEntry(ctx, xauthFile.Name(), display)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return xAuthEntry, nil
}

func readXAuthEntry(ctx context.Context, xauthFile, display string) (*xAuthEntry, error) {
	out, err := runXAuthCommand(ctx, xauthFile, "list", display)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Ignore entries beyond the first listed
	entry := bytes.Split(out, []byte("\n"))[0]
	xAuthEntry, err := parseXAuthEntry(entry)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return xAuthEntry, nil
}

type xAuthEntry struct {
	display *display
	proto   string
	token   string
}

func parseXAuthEntry(entry []byte) (*xAuthEntry, error) {
	splitEntry := strings.Split(string(entry), " ")
	if len(splitEntry) != 3 {
		return nil, trace.BadParameter("invalid xAuthEntry, expected a single three-part entry")
	}

	display, err := displayFromString(splitEntry[0])
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &xAuthEntry{
		display: display,
		proto:   splitEntry[1],
		token:   splitEntry[2],
	}, nil
}

func generateXAuthEntry(ctx context.Context, xauthFile, display, authProto string, trusted bool, ttl time.Duration) error {
	args := []string{"generate", display, authProto}
	if !trusted {
		args = append(args, "untrusted")
	}

	if ttl != 0 {
		// Add some slack to the ttl to avoid XServer from denying
		// access to the ssh session during its lifetime.
		ttl += time.Minute
		args = append(args, "timeout", fmt.Sprintf("%.0f", ttl.Minutes()))
	}

	_, err := runXAuthCommand(ctx, xauthFile, args...)
	return trace.Wrap(err)
}
