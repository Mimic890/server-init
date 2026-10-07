package ufw

import (
	"fmt"
	"strings"
)

// Files edited by the module (ufw has no drop-in directory for them).
const (
	AfterRules  = "/etc/ufw/after.rules"
	After6Rules = "/etc/ufw/after6.rules"
	DefaultFile = "/etc/default/ufw"
)

// Markers of the DOCKER-USER block. They are the ones of the ufw-docker
// project (github.com/chaifeng/ufw-docker), so both tools recognise it.
const (
	dockerBegin = "# BEGIN UFW AND DOCKER"
	dockerEnd   = "# END UFW AND DOCKER"
)

// Comment marks the rules server-init owns.
const Comment = "server-init"

// DockerBlock renders the DOCKER-USER rules that make published container
// ports obey ufw. v6 renders the after6.rules variant.
func DockerBlock(v6 bool) string {
	pre, cidrs := "ufw", []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	if v6 {
		pre, cidrs = "ufw6", []string{"fd00::/8"}
	}
	var b strings.Builder
	fmt.Fprintf(&b, `%s
*filter
:%s-user-forward - [0:0]
:%s-docker-logging-deny - [0:0]
:DOCKER-USER - [0:0]
-A DOCKER-USER -j %s-user-forward

-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A DOCKER-USER -m conntrack --ctstate INVALID -j DROP
-A DOCKER-USER -i docker0 -o docker0 -j ACCEPT

`, dockerBegin, pre, pre, pre)
	for _, c := range cidrs {
		fmt.Fprintf(&b, "-A DOCKER-USER -j RETURN -s %s\n", c)
	}
	for _, c := range cidrs {
		fmt.Fprintf(&b, "-A DOCKER-USER -j %s-docker-logging-deny -m conntrack --ctstate NEW -d %s\n", pre, c)
	}
	fmt.Fprintf(&b, `
-A DOCKER-USER -j RETURN

-A %s-docker-logging-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW DOCKER BLOCK] "
-A %s-docker-logging-deny -j DROP

COMMIT
%s
`, pre, pre, dockerEnd)
	return b.String()
}

// HasDockerBlock reports whether the rules file already has the block (ours
// or one written by ufw-docker).
func HasDockerBlock(content string) bool { return strings.Contains(content, dockerBegin) }

// WithDockerBlock appends the block to the rules file content.
func WithDockerBlock(content string, v6 bool) string {
	if HasDockerBlock(content) {
		return content
	}
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + "\n" + DockerBlock(v6)
}

// Rule is one ufw rule as `ufw show added` prints it (without "ufw ").
type Rule string

// Wanted rules.
func limitRule(port int, what string) Rule {
	return Rule(fmt.Sprintf("limit %d/tcp comment '%s %s'", port, what, Comment))
}

func allowRule(port int, what string) Rule {
	return Rule(fmt.Sprintf("allow %d/tcp comment '%s %s'", port, what, Comment))
}

func ifaceRule(iface string) Rule {
	return Rule(fmt.Sprintf("allow in on %s comment 'trusted interface %s'", iface, Comment))
}

// Args splits a rule into ufw arguments (the comment is one argument).
func (r Rule) Args() []string {
	s := string(r)
	var comment string
	if i := strings.Index(s, " comment '"); i >= 0 {
		comment = strings.TrimSuffix(s[i+len(" comment '"):], "'")
		s = s[:i]
	}
	args := strings.Fields(s)
	if comment != "" {
		args = append(args, "comment", comment)
	}
	return args
}

// DeleteArgs is the `ufw delete ...` form of a rule (without the comment).
func (r Rule) DeleteArgs() []string {
	a := r.Args()
	if n := len(a); n >= 2 && a[n-2] == "comment" {
		a = a[:n-2]
	}
	return append([]string{"delete"}, a...)
}

// ParseAdded reads `ufw show added` output.
func ParseAdded(out string) []Rule {
	var rules []Rule
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if r, ok := strings.CutPrefix(l, "ufw "); ok {
			rules = append(rules, Rule(r))
		}
	}
	return rules
}
