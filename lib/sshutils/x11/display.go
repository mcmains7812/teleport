package x11

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/gravitational/trace"
)

type display struct {
	hostName      string
	displayNumber int
	screenNumber  int
}

func (d *display) String() string {
	return fmt.Sprintf("%s:%d.%d", d.hostName, d.displayNumber, d.screenNumber)
}

func (d *display) Dial() (net.Conn, error) {
	// display is a unix socket, return the default x11 unix socket address
	if d.hostName == "unix" || d.hostName == "" {
		sock := filepath.Join(os.TempDir(), x11UnixSocket, fmt.Sprintf("X%d", d.displayNumber))
		return net.Dial("unix", sock)
	}
	// generic display, dial the display itself (?)
	return net.Dial("unix", d.String())
}

func displayFromEnv() (*display, error) {
	display := os.Getenv(DisplayEnv)
	if display == "" {
		return nil, trace.BadParameter("$DISPLAY is not set")
	}
	return displayFromString(display)
}

// parseDisplay parses the given display value from the form "hostname:display_number.screen_number"
// and returns the host, display number, and screen number; or an error.
func displayFromString(displayString string) (*display, error) {
	if !validDisplay(displayString) {
		return nil, trace.BadParameter("\"%s\" is not a valid display", displayString)
	}

	display := &display{}

	colonIdx := strings.LastIndex(displayString, ":")
	if colonIdx == -1 {
		colonIdx = len(displayString)
	}
	display.hostName = displayString[:colonIdx]

	if colonIdx == len(displayString) {
		return display, nil
	}

	dotIdx := strings.LastIndex(displayString, ".")
	if dotIdx == -1 {
		dotIdx = len(displayString)
	}

	var err error
	display.displayNumber, err = strconv.Atoi(displayString[colonIdx+1 : dotIdx])
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if dotIdx == len(displayString) {
		return display, nil
	}

	display.screenNumber, err = strconv.Atoi(displayString[dotIdx+1:])
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return display, nil
}

func validDisplay(display string) bool {
	isValidSpecialChar := func(r rune) bool {
		return r != ':' && r != '/' && r != '.' && r != '-' && r != '_'
	}
	for _, c := range display {
		if !unicode.IsLetter(c) && !unicode.IsNumber(c) && !isValidSpecialChar(c) {
			return false
		}
	}
	return true
}
