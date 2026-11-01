# Mobile Codex SSH

An SSH plugin for mobile Codex. Run commands on any SSH server from your iPhone
and receive the results in chat, using your linked Mac's OpenSSH client, keys,
and agent.

Your Mac must remain awake and online, with Codex remote access enabled. This
plugin runs on the Mac; it does not connect independently from the iPhone.
End-to-end iPhone use has not yet been verified for this release.

## Install on your Mac

Requires Python 3.11+, OpenSSH, Git, and the Codex CLI available on your `PATH`.
Set up [Codex remote connections](https://learn.chatgpt.com/docs/remote-connections)
to access the Mac from your iPhone.

```sh
git clone https://github.com/goldberg-consulting/mobile-codex-ssh.git
cd mobile-codex-ssh
python3 install.py
```

The installer creates an isolated runtime at `~/.local/share/codex-ssh-client`
and a local marketplace at `~/.codex/local-marketplaces/ssh-client`, then installs
`ssh-client@personal-ssh`. Dependencies are pinned in `requirements.lock`.
It preserves other plugin settings and does not change SSH configuration or keys.
A completed installation is never overwritten; an interrupted installation can
be resumed by running the installer again.

## Use from your iPhone

Open a new Codex chat connected to your Mac and select **SSH Client**. If the
plugin does not appear, restart Codex on the Mac and open a new chat.

- “SSH to example.com as deploy and check disk space.”
- “Connect to 192.0.2.10 as deploy on port 2222 and run uname -a.”
- “On devbox, run cd /srv/app && git status --short.”

Hostnames, IP addresses, and aliases from your Mac's SSH configuration are
supported. Authentication uses keys or an SSH agent on the Mac. Encrypted keys
must already be available through the agent or a working Keychain setup. For a
new server, verify its host fingerprint and connect from the Mac first: the
plugin requires an already trusted host key. Keep private keys out of chat.

Each command runs in a fresh shell and returns stdout, stderr, and its exit
status. There is no interactive terminal, password prompt, SFTP interface, or
persistent shell session.

### Using sudo

This plugin has no private password-entry channel. Do not put a sudo password in
chat, tool arguments, or a command such as `echo password | sudo -S`: that would
expose the password in the conversation or command history. Run commands that
require a password in a trusted interactive SSH terminal instead.

For commands already authorized to run without a prompt, use `sudo -n` so sudo
fails promptly if it needs authentication. A previous terminal login does not
guarantee that a new plugin SSH session can reuse its sudo authorization.

### Mobile password prompt compatibility

A separate, password-free URL prompt test displayed a popup on an iPhone and
returned `action: accept`, but Safari did not open. This verifies the consent
prompt only; it does not verify browser navigation or password authentication.
The result is specific to that tested setup, not a claim about every iOS client.

[Codex documents MCP URL elicitation](https://learn.chatgpt.com/docs/app-server),
but an accepted request is not proof that an external page opened. A future
password flow would need a separately authenticated HTTPS page and independent
confirmation that the external operation completed. This release does not
include that page or any password-entry support.

## Command behavior

The `ssh_exec` tool accepts `host`, `command`, optional `user`, optional `port`,
and `timeout_seconds` (default 30, maximum 120). Pass usernames separately from
the host. Omitted user and port values use your Mac's OpenSSH settings.

Output is limited to 64 KiB across stdout and stderr; `output_truncated` indicates
when that limit was reached. A timeout or disconnect can leave a remote command
running. When `outcome_unknown` is true, check the server before retrying.
Each plugin process permits up to four concurrent commands. Codex's permission
policy controls command approvals.

## Uninstall

```sh
codex plugin remove ssh-client@personal-ssh
```

This removes the plugin from Codex. The runtime and local marketplace directories
listed above remain on your Mac.

## Development

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
```

Tests cover input validation, process cleanup, output limits, and MCP tool calls.
To verify mobile access, ask the plugin to run `uname -s` on a trusted server
from an iPhone chat connected to the Mac.

See the [OpenAI plugin documentation](https://developers.openai.com/plugins/build/plugins)
for plugin packaging and local marketplaces.
