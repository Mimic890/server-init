package audit

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/mimic890/server-init/internal/check"
	"github.com/mimic890/server-init/internal/sys"
)

// listener is one listening socket.
type listener struct {
	Proto   string // tcp, udp
	Addr    string // 0.0.0.0, ::, 127.0.0.1, *
	Port    int
	Process string // first process name, "" when unknown
}

// Public reports whether the socket listens on all or on non-loopback
// addresses.
func (l listener) Public() bool {
	a := strings.Trim(l.Addr, "[]")
	if i := strings.Index(a, "%"); i >= 0 { // fe80::1%eth0
		a = a[:i]
	}
	if a == "*" || a == "0.0.0.0" || a == "::" {
		return true
	}
	ip, err := netip.ParseAddr(a)
	return err == nil && !ip.IsLoopback()
}

var procRe = regexp.MustCompile(`users:\(\("([^"]+)"`)

// ParseListeners parses `ss -H -tulpn`.
func ParseListeners(out string) []listener {
	var ls []listener
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		local := f[4]
		i := strings.LastIndex(local, ":")
		if i < 0 {
			continue
		}
		port, err := strconv.Atoi(local[i+1:])
		if err != nil {
			continue
		}
		l := listener{Proto: f[0], Addr: local[:i], Port: port}
		if m := procRe.FindStringSubmatch(line); m != nil {
			l.Process = m[1]
		}
		ls = append(ls, l)
	}
	return ls
}

// riskyPorts are services that must not be reachable from the internet.
var riskyPorts = map[int]string{
	21: "FTP", 23: "telnet", 111: "rpcbind", 139: "SMB", 445: "SMB", 873: "rsync", 1433: "MS SQL",
	2049: "NFS", 2375: "Docker API (no TLS)", 2376: "Docker API", 2379: "etcd", 3306: "MySQL/MariaDB",
	3389: "RDP", 4369: "Erlang epmd", 5432: "PostgreSQL", 5601: "Kibana", 5672: "RabbitMQ",
	5900: "VNC", 5984: "CouchDB", 6379: "Redis", 8086: "InfluxDB", 8500: "Consul", 9042: "Cassandra",
	9090: "Prometheus", 9200: "Elasticsearch", 9300: "Elasticsearch", 10250: "kubelet",
	11211: "Memcached", 15672: "RabbitMQ admin", 27017: "MongoDB",
}

func (h *host) loadNetwork() {
	if out, err := h.query("ss", "-H", "-tulpn"); err == nil {
		h.listeners = ParseListeners(out)
	}
	if sys.Has(h.s, "ufw") {
		if out, err := h.query("ufw", "status", "verbose"); err == nil && strings.Contains(out, "Status: active") {
			h.ufwStatus = out
		}
	}
}

// ufwAllows reports whether the active ufw has an allow/limit rule for port.
func ufwAllows(status string, port int, proto string) bool {
	p := strconv.Itoa(port)
	for _, l := range strings.Split(status, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || !strings.HasPrefix(f[1], "ALLOW") && !strings.HasPrefix(f[1], "LIMIT") {
			continue
		}
		to := f[0]
		if to == "Anywhere" || to == "Anywhere (v6)" {
			return true
		}
		port, pr, _ := strings.Cut(to, "/")
		if pr != "" && pr != proto {
			continue
		}
		for _, part := range strings.Split(port, ",") {
			lo, hi, isRange := strings.Cut(part, ":")
			if part == p || isRange && between(p, lo, hi) {
				return true
			}
		}
	}
	return false
}

func between(p, lo, hi string) bool {
	n, _ := strconv.Atoi(p)
	a, _ := strconv.Atoi(lo)
	b, _ := strconv.Atoi(hi)
	return n >= a && n <= b
}

func (h *host) networkChecks() {
	if h.listeners == nil {
		h.add(catNetwork, "Open ports", check.Skip, "cannot list sockets (ss)", nil, "")
		return
	}
	dockerFix := strings.Contains(h.read("/etc/ufw/after.rules"), "BEGIN UFW AND DOCKER")
	NetworkChecks(h.r, h.listeners, h.ufwStatus, dockerFix)
}

// NetworkChecks judges the listening sockets against the firewall.
func NetworkChecks(r *check.Report, ls []listener, ufwStatus string, dockerFix bool) {
	add := func(title string, st check.Status, summary string, details []string, fix string) {
		r.Add(check.Finding{Category: catNetwork, Title: title, Status: st, Summary: summary, Details: details, Fix: fix})
	}
	var public []string
	var exposed, blocked []string
	seen := map[string]bool{}
	for _, l := range ls {
		if !l.Public() {
			continue
		}
		key := fmt.Sprintf("%s/%d", l.Proto, l.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		proc := l.Process
		if proc == "" {
			proc = "?"
		}
		public = append(public, fmt.Sprintf("%-4s %-5d %s", l.Proto, l.Port, proc))
		name, risky := riskyPorts[l.Port]
		if !risky {
			continue
		}
		desc := fmt.Sprintf("%d/%s %s (%s)", l.Port, l.Proto, name, proc)
		switch {
		case ufwStatus == "":
			exposed = append(exposed, desc+" - no firewall")
		case proc == "docker-proxy" && !dockerFix:
			exposed = append(exposed, desc+" - published by Docker, bypasses ufw")
		case ufwAllows(ufwStatus, l.Port, l.Proto):
			exposed = append(exposed, desc+" - allowed in ufw")
		default:
			blocked = append(blocked, desc)
		}
	}
	slices.Sort(public)
	add("Open ports", check.Info, fmt.Sprintf("%d service(s) listen on public addresses", len(public)), public, "")
	switch {
	case len(exposed) > 0:
		add("Databases and admin services", check.Fail, "reachable from the internet",
			exposed, "bind them to 127.0.0.1 in their config, or close the port: server-init → Manage → Firewall")
	case len(blocked) > 0:
		add("Databases and admin services", check.Warn, "listen on all addresses, only the firewall blocks them",
			blocked, "bind them to 127.0.0.1 in their config")
	default:
		add("Databases and admin services", check.OK, "none reachable from outside", nil, "")
	}
}

func (h *host) firewallChecks() {
	add := func(title string, st check.Status, summary string, details []string, fix string) {
		h.add(catFirewall, title, st, summary, details, fix)
	}
	switch {
	case h.ufwStatus != "":
		var d []string
		for _, l := range strings.Split(h.ufwStatus, "\n") {
			if strings.HasPrefix(l, "Default:") {
				d = append(d, strings.TrimSpace(l))
			}
		}
		if len(d) > 0 && !strings.Contains(d[0], "deny (incoming)") && !strings.Contains(d[0], "reject (incoming)") {
			add("Firewall", check.Warn, "ufw is active but allows incoming traffic by default", d, fixFirewall)
		} else {
			add("Firewall", check.OK, "ufw is active", d, "")
		}
	case h.otherFirewall():
		add("Firewall", check.OK, "nftables/iptables rules drop incoming traffic", nil, "")
	default:
		add("Firewall", check.Fail, "no firewall: every listening port is reachable", nil, fixFirewall)
	}

	if sys.Has(h.s, "docker") && h.ufwStatus != "" && !strings.Contains(h.read("/etc/ufw/after.rules"), "BEGIN UFW AND DOCKER") {
		add("Docker and ufw", check.Warn, "ports published by Docker bypass ufw", nil, fixFirewall)
	}

	if !sys.Has(h.s, "fail2ban-client") {
		add("fail2ban", check.Warn, "not installed: nothing bans IPs that keep failing to log in", nil, fixF2B)
		return
	}
	out, err := h.query("fail2ban-client", "status")
	switch {
	case err != nil:
		add("fail2ban", check.Warn, "installed but not running", nil, fixF2B)
	case !strings.Contains(out, "sshd"):
		add("fail2ban", check.Warn, "running, but no sshd jail", nil, fixF2B)
	default:
		add("fail2ban", check.OK, "sshd jail active", nil, "")
	}
}

// otherFirewall reports nftables/iptables rules with a dropping input chain.
func (h *host) otherFirewall() bool {
	if out, err := h.query("nft", "list", "ruleset"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, "hook input") && (strings.Contains(l, "policy drop") || strings.Contains(l, "policy reject")) {
				return true
			}
		}
	}
	if out, err := h.query("iptables", "-S", "INPUT"); err == nil && strings.Contains(out, "-P INPUT DROP") {
		return true
	}
	return false
}
