# Screenshot of the apply screen with the SSH login confirmation dialog.
# Same container setup as demo.tape; answering "no" rolls everything back.
Output out/apply.gif

Set Shell "bash"
Set FontSize 15
Set Width 1280
Set Height 820
Set Padding 18
Set Theme "Catppuccin Mocha"

Hide
Type "source docs/vhs/env.sh" Enter
Sleep 500ms
Show

Type "server-init --only ssh,ufw" Enter
Sleep 3s
Enter Sleep 1.5s Enter Sleep 1.5s
# ssh: defaults, generated key shown once
Enter Sleep 500ms Enter Sleep 500ms Down Enter Sleep 500ms Enter Sleep 500ms Enter Sleep 500ms
Enter Sleep 500ms Enter Enter Enter Sleep 500ms Enter Enter Enter Enter Sleep 500ms
# ufw
Enter Enter Enter Enter Sleep 3s
Type "y"
Sleep 8s
Screenshot docs/img/apply-confirm.png
Type "no" Enter
Sleep 6s
Screenshot docs/img/apply-rollback.png
