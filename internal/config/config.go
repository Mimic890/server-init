// Package config holds every answer the user can give, with defaults, and
// loads/saves them as YAML (--config answers.yaml).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"go.yaml.in/yaml/v3"
)

// Answers is the full set of answers for all modules.
type Answers struct {
	// Modules to run. Empty means all v1 modules.
	Modules  []string `yaml:"modules,omitempty"`
	System   System   `yaml:"system"`
	Cleanup  Cleanup  `yaml:"cleanup"`
	Users    Users    `yaml:"users"`
	SSH      SSH      `yaml:"ssh"`
	UFW      UFW      `yaml:"ufw"`
	Fail2ban Fail2ban `yaml:"fail2ban"`
	Sysctl   Sysctl   `yaml:"sysctl"`
}

// System module answers.
type System struct {
	Upgrade            bool     `yaml:"upgrade"`
	Hostname           string   `yaml:"hostname"`
	Timezone           string   `yaml:"timezone"`
	Locale             string   `yaml:"locale"`
	NTP                bool     `yaml:"ntp"`
	UnattendedUpgrades bool     `yaml:"unattended_upgrades"`
	AutoReboot         bool     `yaml:"auto_reboot"`
	AutoRebootTime     string   `yaml:"auto_reboot_time"`
	Packages           []string `yaml:"packages"`
}

// Cleanup module answers.
type Cleanup struct {
	RemoveSnapd     bool   `yaml:"remove_snapd"`
	RemoveCloudInit bool   `yaml:"remove_cloud_init"`
	RemovePopcon    bool   `yaml:"remove_popularity_contest"`
	DisableMotdNews bool   `yaml:"disable_motd_news"`
	Autoremove      bool   `yaml:"autoremove"`
	JournaldMaxUse  string `yaml:"journald_max_use"`
}

// Users module answers.
type Users struct {
	// CreateAdmin creates (or adopts) Name as the admin user. False keeps
	// root as the only admin (key-only login).
	CreateAdmin bool   `yaml:"create_admin"`
	Name        string `yaml:"name"`
	// SudoNoPassword grants NOPASSWD sudo. Otherwise the user needs a
	// password: PasswordHash (crypt(3), e.g. from `openssl passwd -6`) or
	// one typed in the TUI.
	SudoNoPassword bool     `yaml:"sudo_nopasswd"`
	PasswordHash   string   `yaml:"password_hash,omitempty"`
	Password       string   `yaml:"-"` // TUI only, never saved
	ExtraGroups    []string `yaml:"extra_groups"`
	LockRoot       bool     `yaml:"lock_root_password"`
	Umask027       bool     `yaml:"umask_027"`
}

// SSH module answers (same questions as ssh-setup.sh).
type SSH struct {
	Port int `yaml:"port"` // 0 = random free port
	// User to log in with. Empty = the users module admin, or root.
	User      string `yaml:"user"`
	GrantSudo bool   `yaml:"grant_sudo"` // NOPASSWD sudo when ssh creates the user itself
	// KeyMode is "paste" or "generate".
	KeyMode    string `yaml:"key_mode"`
	PublicKey  string `yaml:"public_key"`
	Passphrase bool   `yaml:"passphrase"`
	// KeyKeep is "keep" or "show" (show once, delete after confirmed login).
	KeyKeep         string `yaml:"key_keep"`
	AllowOnly       bool   `yaml:"allow_only_user"`
	MaxAuthTries    int    `yaml:"max_auth_tries"`
	LoginGraceTime  int    `yaml:"login_grace_time"`
	ClientAlive     bool   `yaml:"client_alive"`
	X11Forwarding   bool   `yaml:"x11_forwarding"`
	TCPForwarding   string `yaml:"tcp_forwarding"` // no | local | yes
	AgentForwarding bool   `yaml:"agent_forwarding"`
	Banner          string `yaml:"banner"`
	// OpenFirewall opens the new port in an already active ufw/firewalld.
	OpenFirewall bool `yaml:"open_firewall"`
}

// UFW module answers.
type UFW struct {
	AllowHTTP  bool     `yaml:"allow_http"`
	AllowHTTPS bool     `yaml:"allow_https"`
	Interfaces []string `yaml:"trusted_interfaces"` // e.g. tailscale0, wg0
	DockerFix  bool     `yaml:"docker_fix"`
}

// Fail2ban module answers.
type Fail2ban struct {
	MaxRetry        int      `yaml:"maxretry"`
	FindTime        string   `yaml:"findtime"`
	BanTime         string   `yaml:"bantime"`
	Recidive        bool     `yaml:"recidive"`
	WhitelistClient bool     `yaml:"whitelist_client_ip"`
	Whitelist       []string `yaml:"whitelist"`
}

// Sysctl module answers.
type Sysctl struct {
	BBR        bool   `yaml:"bbr"`
	Hardening  bool   `yaml:"hardening"`
	SwapSize   string `yaml:"swap_size"` // e.g. 2G; "" or "0" = no swap file
	Swappiness int    `yaml:"swappiness"`
}

// Default returns the recommended answers.
func Default() *Answers {
	return &Answers{
		System: System{
			Upgrade:            true,
			NTP:                true,
			UnattendedUpgrades: true,
			AutoReboot:         false,
			AutoRebootTime:     "04:00",
			Packages:           []string{"curl", "git", "htop", "jq", "unzip", "ncdu"},
		},
		Cleanup: Cleanup{
			DisableMotdNews: true,
			Autoremove:      true,
			JournaldMaxUse:  "200M",
		},
		Users: Users{
			CreateAdmin:    true,
			Name:           "admin",
			SudoNoPassword: true,
			ExtraGroups:    nil,
			LockRoot:       true,
			Umask027:       true,
		},
		SSH: SSH{
			KeyMode:        "paste",
			KeyKeep:        "show",
			AllowOnly:      true,
			MaxAuthTries:   3,
			LoginGraceTime: 30,
			ClientAlive:    true,
			TCPForwarding:  "no",
			OpenFirewall:   true,
		},
		UFW: UFW{
			DockerFix: true,
		},
		Fail2ban: Fail2ban{
			MaxRetry:        3,
			FindTime:        "10m",
			BanTime:         "1h",
			Recidive:        true,
			WhitelistClient: true,
		},
		Sysctl: Sysctl{
			BBR:        true,
			Hardening:  true,
			SwapSize:   "",
			Swappiness: 10,
		},
	}
}

// Load reads YAML on top of the defaults: keys missing in the file keep
// their default value. Unknown keys are an error (typos must not silently
// fall back to defaults).
func Load(path string) (*Answers, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse is Load for an in-memory document.
func Parse(b []byte) (*Answers, error) {
	a := Default()
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(a); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("config: %w", err)
	}
	return a, nil
}

// Marshal renders answers as YAML.
func Marshal(a *Answers) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("# server-init answers - use with: server-init --config <this file>\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(a); err != nil {
		return nil, err
	}
	return buf.Bytes(), enc.Close()
}
