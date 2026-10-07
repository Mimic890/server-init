package audit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/mimic890/server-init/internal/check"
	"github.com/mimic890/server-init/internal/sys"
)

// DialTLS connects to addr and returns the leaf certificate. maxVersion
// limits the TLS version (0 = default). Tests replace it.
var DialTLS = func(ctx context.Context, addr, serverName string, maxVersion uint16) (*x509.Certificate, error) {
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 3 * time.Second},
		Config: &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true, //nolint:gosec // we only read the certificate and the protocol version
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         maxVersion,
		},
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	certs := c.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate")
	}
	return certs[0], nil
}

// now is replaced in tests.
var now = time.Now

var (
	nginxTokensRe    = regexp.MustCompile(`(?m)^\s*server_tokens\s+off\s*;`)
	nginxAutoindexRe = regexp.MustCompile(`(?m)^\s*autoindex\s+on\s*;`)
	nginxProtoRe     = regexp.MustCompile(`(?m)^\s*ssl_protocols\s+([^;]*);`)
	apacheIndexesRe  = regexp.MustCompile(`(?mi)^\s*Options\s+([^\n]*)`)
)

func (h *host) webChecks() {
	found := false
	if sys.Has(h.s, "nginx") {
		found = true
		if out, err := h.query("nginx", "-T"); err == nil {
			NginxChecks(h.r, out)
		} else {
			h.add(catWeb, "nginx", check.Skip, "cannot read the configuration (nginx -T)", nil, "")
		}
	}
	if sys.Has(h.s, "apache2ctl") || sys.Exists(h.s, "/etc/apache2/apache2.conf") {
		found = true
		conf := h.read("/etc/apache2/apache2.conf") + "\n" + h.read("/etc/apache2/conf-enabled/security.conf")
		sites, _ := h.s.Glob("/etc/apache2/sites-enabled/*")
		for _, s := range sites {
			conf += "\n" + h.read(s)
		}
		ApacheChecks(h.r, conf)
	}
	for _, l := range h.listeners {
		if l.Proto == "tcp" && l.Port == 443 && l.Public() {
			found = true
			h.tlsCheck()
			break
		}
	}
	if !found {
		h.add(catWeb, "Web server", check.Info, "no nginx, Apache or HTTPS port found", nil, "")
	}
}

// NginxChecks judges `nginx -T` output.
func NginxChecks(r *check.Report, conf string) {
	add := func(title string, st check.Status, summary string, details []string, fix string) {
		r.Add(check.Finding{Category: catWeb, Title: title, Status: st, Summary: summary, Details: details, Fix: fix})
	}
	if nginxTokensRe.MatchString(conf) {
		add("nginx version banner", check.OK, "hidden", nil, "")
	} else {
		add("nginx version banner", check.Warn, "nginx shows its version in headers and error pages", nil, "add 'server_tokens off;' to the http block")
	}
	if nginxAutoindexRe.MatchString(conf) {
		add("nginx directory listing", check.Warn, "autoindex on: directory contents are listed", nil, "remove 'autoindex on;' unless it is intended")
	}
	var old []string
	for _, m := range nginxProtoRe.FindAllStringSubmatch(conf, -1) {
		for _, p := range strings.Fields(m[1]) {
			if p == "TLSv1" || p == "TLSv1.1" || strings.HasPrefix(p, "SSL") {
				old = append(old, p)
			}
		}
	}
	if len(old) > 0 {
		add("nginx TLS versions", check.Warn, "outdated protocols enabled: "+strings.Join(old, " "), nil, "ssl_protocols TLSv1.2 TLSv1.3;")
	}
}

// ApacheChecks judges the Apache configuration files.
func ApacheChecks(r *check.Report, conf string) {
	add := func(title string, st check.Status, summary string, details []string, fix string) {
		r.Add(check.Finding{Category: catWeb, Title: title, Status: st, Summary: summary, Details: details, Fix: fix})
	}
	tokens, sig := "", ""
	for _, l := range lines(conf) {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		switch strings.ToLower(f[0]) {
		case "servertokens":
			tokens = strings.ToLower(f[1])
		case "serversignature":
			sig = strings.ToLower(f[1])
		}
	}
	if (tokens == "prod" || tokens == "productonly") && sig == "off" {
		add("Apache version banner", check.OK, "hidden", nil, "")
	} else {
		add("Apache version banner", check.Warn, "Apache shows its version", nil,
			"ServerTokens Prod and ServerSignature Off in /etc/apache2/conf-available/security.conf")
	}
	listing := false
	for _, m := range apacheIndexesRe.FindAllStringSubmatch(conf, -1) {
		for _, o := range strings.Fields(m[1]) {
			if o == "Indexes" || o == "+Indexes" {
				listing = true
			}
		}
	}
	if listing {
		add("Apache directory listing", check.Warn, "Options Indexes: directory contents are listed", nil, "use 'Options -Indexes'")
	}
}

func (h *host) tlsCheck() {
	name := strings.TrimSpace(h.read("/etc/hostname"))
	cert, err := DialTLS(h.ctx, "127.0.0.1:443", name, 0)
	if err != nil {
		h.add(catWeb, "HTTPS certificate", check.Skip, "cannot connect to port 443: "+err.Error(), nil, "")
		return
	}
	TLSCertCheck(h.r, cert, now())
	if _, err := DialTLS(h.ctx, "127.0.0.1:443", name, tls.VersionTLS11); err == nil {
		h.add(catWeb, "HTTPS TLS versions", check.Warn, "TLS 1.0/1.1 are still accepted", nil, "allow only TLS 1.2 and 1.3")
	} else {
		h.add(catWeb, "HTTPS TLS versions", check.OK, "TLS 1.2+ only", nil, "")
	}
}

// TLSCertCheck judges the expiry of the HTTPS certificate.
func TLSCertCheck(r *check.Report, c *x509.Certificate, t time.Time) {
	add := func(st check.Status, summary string) {
		r.Add(check.Finding{Category: catWeb, Title: "HTTPS certificate", Status: st, Summary: summary,
			Fix: "renew it (certbot renew)"})
	}
	left := c.NotAfter.Sub(t)
	subject := c.Subject.CommonName
	if len(c.DNSNames) > 0 {
		subject = strings.Join(c.DNSNames, ", ")
	}
	switch {
	case left < 0:
		add(check.Fail, fmt.Sprintf("%s expired on %s", subject, c.NotAfter.Format("2006-01-02")))
	case left < 14*24*time.Hour:
		add(check.Warn, fmt.Sprintf("%s expires in %d day(s)", subject, int(left.Hours()/24)))
	default:
		add(check.OK, fmt.Sprintf("%s valid until %s", subject, c.NotAfter.Format("2006-01-02")))
	}
}
