# Demo of the interactive setup in dry-run mode.
# Render: docker run -d --name si-demo --hostname web1 --privileged --cgroupns=host \
#           -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock <test image>
#         docker cp server-init si-demo:/usr/local/bin/
#         vhs docs/vhs/demo.tape
Output docs/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1280
Set Height 820
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Hide
Type "source docs/vhs/env.sh" Enter
Sleep 500ms
Show

Type "server-init --dry-run" Sleep 400ms Enter
Sleep 3s

# Welcome (preflight) -> module picker
Enter
Sleep 2s
# keep ssh, ufw and fail2ban for the demo: unselect system, cleanup, users, sysctl
Type "x" Sleep 300ms Down Type "x" Sleep 300ms Down Type "x" Sleep 300ms
Down Down Down Down Type "x"
Sleep 1.5s
Enter
Sleep 1.5s

# SSH: port, user, key
Enter Sleep 1s
Enter Sleep 1s
Down Sleep 600ms Enter Sleep 1.2s
# passphrase no, show private key once
Enter Sleep 800ms
Enter Sleep 1s
# AllowUsers, limits, forwarding
Enter Sleep 700ms
Enter Sleep 400ms Enter Sleep 400ms Enter Sleep 900ms
Enter Sleep 400ms Enter Sleep 400ms Enter Sleep 400ms Enter Sleep 900ms

# ufw: allow HTTPS
Enter Sleep 500ms Right Sleep 500ms Enter Sleep 500ms Enter Sleep 500ms Enter Sleep 1s

# fail2ban
Enter Sleep 400ms Enter Sleep 400ms Enter Sleep 400ms Enter Sleep 900ms
Enter Sleep 900ms
Enter Sleep 2.5s

# Summary
Sleep 2s
PageDown Sleep 1.5s
PageDown Sleep 1.5s
PageDown Sleep 2.5s
Type "q"
Sleep 1s
