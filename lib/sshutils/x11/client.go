package x11

import (
	"context"

	"github.com/gravitational/teleport/lib/sshutils"

	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// RequestX11Forwarding sends an "x11-req" to the server to set up
// x11 forwarding for the given session.
func RequestX11Forwarding(ctx context.Context, sess *ssh.Session, clt *ssh.Client, trusted, singleConnection bool) error {
	// TODO: GetDisplayEnv and pass to functions higher in call stack
	display, err := displayFromEnv()
	if err != nil {
		return trace.Wrap(err)
	}

	var xauthEntry *xAuthEntry
	if trusted {
		// use existing real auth token
		xauthEntry, err = readXAuthEntry(ctx, "", display.String())
		if err != nil {
			// if we can't get the real auth token, a new fake one will suffice.
			xauthEntry, err = spoofXAuthEntry(&xAuthEntry{
				display: display,
				proto:   xauthProto,
			})
			if err != nil {
				return trace.Wrap(err)
			}
		}
	} else {
		// create a new untrusted auth token
		xauthEntry, err = generateUntrustedXAuthEntry(ctx, display.String(), 0)
		if err != nil {
			return trace.Wrap(err)
		}
	}

	// Create a fake xauth entry which will be used to authenticate incoming
	// server requests. Once the channel is created, the real auth cookie will
	// be used to authorize the XServer.
	// (somehow? Do we actually need to grab the cookie? do we just grab it to make a realistic spoof?)
	fakeXAuthEntry, err := spoofXAuthEntry(xauthEntry)
	if err != nil {
		return trace.Wrap(err)
	}

	if err := StartX11ChannelListener(clt, fakeXAuthEntry); err != nil {
		return trace.Wrap(err)
	}

	payload := X11ForwardRequestPayload{
		SingleConnection: singleConnection,
		AuthProtocol:     xauthEntry.proto,
		AuthCookie:       fakeXAuthEntry.token,
		ScreenNumber:     uint32(display.screenNumber),
	}

	ok, err := sess.SendRequest(sshutils.X11ForwardRequest, true, ssh.Marshal(payload))
	if err != nil {
		return trace.Wrap(err)
	} else if !ok {
		return trace.Errorf("x11 forward request failed")
	}

	return nil
}

// StartX11ChannelListener creates an "x11" request channel to catch any
// "x11" requests to the ssh client and starts a goroutine to handle any
// requests received.
func StartX11ChannelListener(clt *ssh.Client, xauthEntry *xAuthEntry) error {
	nchs := clt.HandleChannelOpen(sshutils.X11ChannelRequest)
	if nchs == nil {
		return trace.AlreadyExists("x11 forwarding channel already open")
	}

	go serveX11ChannelListener(nchs, xauthEntry)
	return nil
}

// serveX11ChannelListener handles new "x11" channel requests and copies
// data between the new ssh channel and the local display.
func serveX11ChannelListener(nchs <-chan ssh.NewChannel, xauthEntry *xAuthEntry) {
	for nch := range nchs {
		// accept downstream X11 channel from server
		sch, _, err := nch.Accept()
		if err != nil {
			log.WithError(err).Warn("failed to accept x11 channel request")
			return
		}

		go func(sch ssh.Channel) {
			defer sch.Close()

			var payload []byte
			if _, err := sch.Read(payload); err != nil {
				log.WithError(err).Warn("x11 channel request is missing payload")
				return
			}

			var x11ChannelReq X11ChannelRequestPayload
			if err := ssh.Unmarshal(payload, &x11ChannelReq); err != nil {
				log.WithError(err).Warn("failed to unmarshal x11 channel request payload")
				return
			}

			log.Infof("received x11 channel request from %s:%s", x11ChannelReq.OriginatorAddress, x11ChannelReq.OriginatorPort)

			if x11ChannelReq.AuthProtocol != xauthEntry.proto || x11ChannelReq.AuthCookie != xauthEntry.token {
				log.WithError(err).Warn("x11 channel request failed to invalid authentication credentials")
				return
			}

			conn, err := xauthEntry.display.Dial()
			if err != nil {
				log.WithError(err).Warn("failed to open connection to x11 unix socket")
				return
			}
			defer conn.Close()

			// copy data between the XClient conn and X11 channel
			linkChannelConn(conn, sch)
		}(sch)
	}
}
