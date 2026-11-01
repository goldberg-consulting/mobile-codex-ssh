# Mobile Codex SSH

An SSH plugin for mobile Codex. Run commands on any SSH server from your iPhone
and receive the results in chat, using your linked Mac's OpenSSH client. Use
Mac keys/agent, or enter SSH and sudo passwords on a separate private HTTPS page.

Your Mac must remain awake and online, with Codex remote access enabled. This
plugin runs on the Mac; it does not connect independently from the iPhone.
Opening an ordinary chat link has been verified on an iPhone. The new password
flow has automated local coverage; an end-to-end iPhone password login still
needs device verification.

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
A completed installation is never overwritten without `--upgrade`; an interrupted
installation can be resumed by running the installer again. To deliberately
upgrade a recognized installation, run `python3 install.py --upgrade`.

## Enable private password entry

The optional helper uses [Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve)
for private HTTPS and the signed-in device's identity. Install Tailscale on the
Mac and iPhone and sign in to both with the same account. Keep Tailscale connected
on the phone when opening a password page. This does not expose a public website.

After installing or upgrading the plugin, run on the Mac:

```sh
python3 setup_secure.py
```

Setup discovers the Mac's Tailscale name and account locally, creates a user
LaunchAgent, and serves the helper through private HTTPS on port 8443. It refuses
to overwrite another service on that port; use `--https-port` to choose another.
If Tailscale requests HTTPS enablement, complete its setup and run this command
again. No account, hostname, or credentials are embedded in this repository.

The helper's configuration lives at `~/.config/codex-ssh/secure.json` (mode 0600).
Its sockets live in `~/.local/share/codex-ssh-client/secure` (directory mode 0700).
Only the configured Tailscale login can view or submit a password request. An ID
or link from chat does not authenticate its holder.

To run the helper in the foreground after configuration:

```sh
PYTHONPATH=src .venv/bin/python -m codex_ssh.helper
```

Do not run a second instance while the LaunchAgent is running. The helper never
listens on a TCP address: Tailscale proxies to its private web socket and Codex
uses a different private control socket. Do not expose the control socket or
replace Tailscale Serve with an untrusted proxy that can forge identity headers.

## Use from your iPhone

Open a new Codex chat connected to your Mac and select **SSH Client**. If the
plugin does not appear, restart Codex on the Mac and open a new chat.

- “SSH to example.com as deploy and check disk space.”
- “Connect to 192.0.2.10 as deploy on port 2222 and run uname -a.”
- “On devbox, run cd /srv/app && git status --short.”

Hostnames, IP addresses, and aliases from your Mac's SSH configuration are
supported. The ordinary `ssh_exec` tool uses keys or an SSH agent on the Mac. Encrypted keys
must already be available through the agent or a working Keychain setup. For a
new server, verify its host fingerprint and connect from the Mac first: the
plugin requires an already trusted host key. Keep private keys out of chat.

Each command runs in a fresh shell and returns stdout, stderr, and its exit
status. There is no interactive terminal, SFTP interface, or persistent shell
session. Password requests use the separate flow below.

### Using sudo

Do not put a password in chat, tool arguments, or a command such as
`echo password | sudo -S`. With the helper configured, ask Codex to use
`ssh_start_secure` with `sudo=true` and give the command without a leading `sudo`.
The page shows the exact command and asks separately for the SSH and sudo
passwords when needed. The helper runs the approved command as root through sudo;
it does not enable password-free sudo or change the server's configuration.

For commands already authorized to run without a prompt, use `sudo -n` so sudo
fails promptly if it needs authentication. A previous terminal login does not
guarantee that a new plugin SSH session can reuse its sudo authorization. Sudo
policies requiring a terminal or interactive MFA are not supported.

### Password flow

1. Ask Codex to start a secure SSH request. For example: “Connect to example.com
   as deploy using password authentication and run uname -s.”
2. Codex calls `ssh_start_secure` and gives you a normal clickable HTTPS link.
   The request has a ten-minute entry deadline. No SSH command starts yet.
3. Open the link on the iPhone, review the destination and exact command, enter
   the requested passwords, and approve execution. You can cancel instead.
4. Return to chat and ask Codex to check `ssh_secure_status`. It returns the
   command result after completion. `ssh_secure_cancel` revokes pending requests
   or stops the local SSH connection; remote work may already have started.

The helper submits passwords through private SSH askpass or stdin pipes, not
through MCP, arguments, environment variables, files, or chat. It stores no
passwords on disk. It drops in-memory references when work ends; Python cannot
guarantee that every memory copy is overwritten. Browser responses disable caching
and use no analytics, third-party scripts, or password logging. The web page
does not show command output.

The SSH password mode supports standard password authentication to a direct
destination. Keyboard-interactive/MFA, private-key passphrase prompts, and password
authentication through ProxyJump/ProxyCommand are not supported. Use existing
Mac keys/agent for `authentication="key"`; a separate sudo password can still
be entered on the page. Host-key checks stay strict in both modes.

The Mac, its local SSH configuration, and the destination server must be trusted.
This keeps passwords out of the normal chat/tool path; it cannot isolate them
from a malicious local administrator, compromised SSH server, or software with
arbitrary access to the Mac. Exact submitted password bytes are redacted from
captured command output as an additional safeguard, not a guarantee against a
server deliberately transforming or leaking them.

### Mobile password prompt compatibility

A separate, password-free URL prompt test displayed a popup on an iPhone and
returned `action: accept`, but Safari did not open. Tapping an ordinary link in
the chat did open the test page on the iPhone. This verifies manual navigation
as a fallback; it does not verify password authentication. These results are
specific to the tested setup, not a claim about every iOS client.

[Codex documents MCP URL elicitation](https://learn.chatgpt.com/docs/app-server),
but an accepted request is not proof that an external page opened. The password
flow therefore uses an explicit link and tracks the actual operation separately.

## Command behavior

The `ssh_exec` tool accepts `host`, `command`, optional `user`, optional `port`,
and `timeout_seconds` (default 30, maximum 120). Pass usernames separately from
the host. Omitted user and port values use your Mac's OpenSSH settings.

Output is limited to 64 KiB across stdout and stderr; `output_truncated` indicates
when that limit was reached. A timeout or disconnect can leave a remote command
running. When `outcome_unknown` is true, check the server before retrying.
Each plugin process permits up to four concurrent commands. Codex's permission
policy controls command approvals.

`ssh_start_secure` adds `authentication` (`password` or `key`) and `sudo` (boolean)
to those command fields and returns an operation ID and URL. It has no credential
parameters. The helper permits up to 32 requests and four running commands;
completed results expire after ten minutes. The command timeout starts after
browser approval, independently of the password-entry deadline.

## Uninstall

```sh
codex plugin remove ssh-client@personal-ssh
```

This removes the plugin from Codex. The runtime and local marketplace directories
listed above remain on your Mac.

If you enabled the helper, stop its user LaunchAgent and disable only its Serve
port before removing the runtime. The setup uses the label
`com.goldbergconsulting.codex-ssh-helper`; removing the plugin alone does not stop
that separate process. Do not use `tailscale serve reset` if you have other services.

## Development

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
```

Tests cover input validation, process cleanup, output limits, and MCP tool calls.
They also cover private socket permissions, browser identity and CSRF checks,
expiry/replay, password redaction, and sudo input isolation. An optional real
OpenSSH test uses only a local fake server and dummy credentials:

```sh
.venv/bin/python -m pip install -r requirements-test.txt
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
```

To verify mobile access, ask the plugin to run `uname -s` on a trusted server
from an iPhone chat connected to the Mac.

See the [OpenAI plugin documentation](https://developers.openai.com/plugins/build/plugins)
for plugin packaging and local marketplaces.
