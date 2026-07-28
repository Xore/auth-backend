package main

// smtp_test.go — transport-security tests for smtpSend: STARTTLS is
// required for smtp://, TLS 1.2+ for smtps://, and plaintext delivery only
// happens with the explicit development opt-in.

import (
	"bufio"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

// fakeSMTP is a minimal single-connection SMTP server for tests. When
// startTLS is set it advertises STARTTLS but then speaks garbage instead of
// TLS, so the client handshake must fail.
type fakeSMTP struct {
	ln       net.Listener
	startTLS bool

	mu   sync.Mutex
	cmds []string
	auth bool
	body string
}

func startFakeSMTP(t *testing.T, startTLS bool) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeSMTP{ln: ln, startTLS: startTLS}
	go f.serve()
	t.Cleanup(func() { _ = f.ln.Close() })
	return f
}

func (f *fakeSMTP) addr() string { return f.ln.Addr().String() }

func (f *fakeSMTP) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cmds...)
}

func (f *fakeSMTP) servedBody() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.body
}

func (f *fakeSMTP) servedAuth() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.auth
}

func (f *fakeSMTP) serve() {
	conn, err := f.ln.Accept()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	write := func(s string) { _, _ = io.WriteString(conn, s) }
	write("220 fake ESMTP ready\r\n")
	inData := false
	var body strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if inData {
			if line == "." {
				inData = false
				f.mu.Lock()
				f.body = body.String()
				f.mu.Unlock()
				write("250 2.0.0 queued\r\n")
			} else {
				body.WriteString(line + "\n")
			}
			continue
		}
		cmd := strings.ToUpper(line)
		f.mu.Lock()
		f.cmds = append(f.cmds, cmd)
		f.mu.Unlock()
		switch {
		case strings.HasPrefix(cmd, "EHLO") || strings.HasPrefix(cmd, "HELO"):
			reply := "250-fake greets you\r\n250-AUTH PLAIN\r\n"
			if f.startTLS {
				reply += "250-STARTTLS\r\n"
			}
			reply += "250 8BITMIME\r\n"
			write(reply)
		case cmd == "STARTTLS":
			write("220 2.0.0 go ahead\r\n")
			write("this is not a TLS handshake\r\n") // garbage: handshake must fail
			return
		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			f.mu.Lock()
			f.auth = true
			f.mu.Unlock()
			write("235 2.7.0 authenticated\r\n")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			write("250 2.1.0 ok\r\n")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			write("250 2.1.5 ok\r\n")
		case cmd == "DATA":
			write("354 end with <CR><LF>.<CR><LF>\r\n")
			inData = true
		case cmd == "QUIT":
			write("221 2.0.0 bye\r\n")
			return
		default:
			write("502 5.5.2 not implemented\r\n")
		}
	}
}

// smtp:// without a STARTTLS offer must fail closed: no credentials and no
// reset link leave the process.
func TestSMTPRequiresSTARTTLS(t *testing.T) {
	f := startFakeSMTP(t, false)
	err := smtpSend("smtp://user:pw@"+f.addr(), "from@x.com", "to@x.com",
		"reset", "https://auth.example.com/reset?token=secret", false)
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("expected STARTTLS refusal, got %v", err)
	}
	for _, c := range f.commands() {
		if strings.HasPrefix(c, "AUTH") || strings.HasPrefix(c, "MAIL") || c == "DATA" {
			t.Fatalf("client sent %q to an unencrypted server", c)
		}
	}
	if f.servedAuth() || strings.Contains(f.servedBody(), "secret") {
		t.Fatal("credentials or reset link sent over plaintext without opt-in")
	}
}

// The explicit development opt-in permits plaintext smtp:// — and only then.
func TestSMTPInsecureOptIn(t *testing.T) {
	f := startFakeSMTP(t, false)
	err := smtpSend("smtp://user:pw@"+f.addr(), "from@x.com", "to@x.com",
		"reset", "the reset link body", true)
	if err != nil {
		t.Fatalf("explicit opt-in should allow plaintext delivery: %v", err)
	}
	if !f.servedAuth() {
		t.Fatal("AUTH PLAIN not sent with opt-in")
	}
	if !strings.Contains(f.servedBody(), "the reset link body") {
		t.Fatalf("message body not delivered: %q", f.servedBody())
	}
}

// A server that advertises STARTTLS but cannot complete the handshake must
// fail — never fall back to plaintext.
func TestSMTPStartTLSFailure(t *testing.T) {
	f := startFakeSMTP(t, true)
	err := smtpSend("smtp://user:pw@"+f.addr(), "from@x.com", "to@x.com",
		"reset", "secret", true) // even the opt-in must not bypass a failed upgrade
	if err == nil {
		t.Fatal("broken STARTTLS handshake accepted")
	}
	if f.servedAuth() || strings.Contains(f.servedBody(), "secret") {
		t.Fatal("credentials or reset link sent after a failed STARTTLS upgrade")
	}
}

// smtps:// requires a working TLS handshake from the first byte.
func TestSMTPImplicitTLSFailure(t *testing.T) {
	f := startFakeSMTP(t, false) // plaintext server: no TLS at all
	err := smtpSend("smtps://user:pw@"+f.addr(), "from@x.com", "to@x.com",
		"reset", "secret", true)
	if err == nil {
		t.Fatal("smtps:// to a plaintext server accepted")
	}
	if strings.Contains(f.servedBody(), "secret") {
		t.Fatal("reset link sent to a non-TLS peer")
	}
}

func TestSMTPSchemeValidation(t *testing.T) {
	for _, rawURL := range []string{
		"http://mail.example.com:25",
		"smtp+ssl://mail.example.com",
		"smtp://",      // no host
		"://not-a-url", // malformed
	} {
		if err := smtpSend(rawURL, "from@x.com", "to@x.com", "s", "b", false); err == nil {
			t.Errorf("smtpSend(%q) accepted an invalid configuration", rawURL)
		}
	}
}
