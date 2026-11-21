# icloud-keys

- [`age-plugin-icloud`](#age-plugin-icloud) lets me decrypt [age](https://age-encryption.org) files on any of my Macs without copying a private key around.
- [`icloud-ssh-agent`](#icloud-ssh-agent) syncs SSH keys the same way. I can sign Git commits without a prompt and still require Touch ID for SSH logins.

I built these for my homelab, with a fair bit of AI help. They haven't had a thorough security review.

Each tool ships as a signed macOS app with its own Keychain access group. Both store exportable private keys in iCloud Keychain. The apps enforce their own Touch ID policies because synced Keychain items can't require it directly. Software with access to an item can read the key and change its policy.

## Install

You'll need an Apple silicon Mac running macOS 14 or later, signed in to your Apple Account with iCloud Keychain enabled.

With Homebrew, install whichever tool you need. The SSH cask needs a tagged SSH agent release.

```sh
brew tap lstoll/tap
brew trust --tap lstoll/tap
brew install --cask age-plugin-icloud
brew install --cask icloud-ssh-agent
```

For a manual install, download the zip for your tool and move the `.app` to `/Applications`. Release tags start with `age-plugin-icloud-v` or `icloud-ssh-agent-v`. The original age release is tagged `v0.1.0`. [Releases](https://github.com/lstoll/icloud-keys/releases)

Symlink the command into a directory on your `PATH`. Keep the executable inside the signed app bundle so it can access iCloud Keychain.

```sh
ln -s /Applications/age-plugin-icloud.app/Contents/MacOS/age-plugin-icloud /usr/local/bin/
ln -s /Applications/icloud-ssh-agent.app/Contents/MacOS/icloud-ssh-agent /usr/local/bin/
```

## age-plugin-icloud

Generate the identity once. The name defaults to `default` and the decryption policy defaults to `5m`.

```sh
mkdir -p ~/.age
age-plugin-icloud --generate > ~/.age/icloud.txt
```

That file contains a reference to the Keychain item and the public `age1pq1...` recipient in a comment. The ML-KEM-768/X25519 private key stays in Keychain. To recreate the file after the key has synced to another Mac, run `mkdir -p ~/.age` and `age-plugin-icloud --list --name default > ~/.age/icloud.txt`.

Pick an access mode when you generate an identity, for example `age-plugin-icloud --generate --name work --access-control=everyTime`.

| Mode | Decryption |
| --- | --- |
| `none` | No prompt |
| `everyTime` | Ask for Touch ID or your Mac password each time you run age |
| `5m` | Reuse a recent approval on this Mac. A recent Touch ID unlock can also count. |

Anyone with the public recipient can encrypt with age 1.3.2 or later. Run `age -r age1pq1... -o secret.age file`, substituting your full recipient. On a Mac with the plugin installed, you can use the identity file in both directions.

```sh
age -e -i ~/.age/icloud.txt -o secret.age file
age -d -i ~/.age/icloud.txt -o file.decrypted secret.age
```

You can also use `-j icloud` in place of `-i ~/.age/icloud.txt`. It encrypts to `default` and tries all stored identities when decrypting.

`--set-access-control` and `--export` were added after v0.1.0 and always ask for approval. Export prints the private key in age's native format. Use a new filename for the export.

```sh
age-plugin-icloud --list
age-plugin-icloud --set-access-control --name work --access-control=everyTime
(umask 077; age-plugin-icloud --export --name work > work.key)
```

`age-plugin-icloud --delete --name work` removes the identity from iCloud Keychain and syncs that deletion to your other devices.

## icloud-ssh-agent

### Set up

```sh
icloud-ssh-agent install
icloud-ssh-agent generate work
icloud-ssh-agent status
icloud-ssh-agent public-key work
```

`install` registers the agent as a login item. If macOS asks for approval, go to System Settings → General → Login Items. Add the public key to the server or Git host you want to log in to, then point SSH at the agent in `~/.ssh/config`.

```sshconfig
Host *
  IdentityAgent ~/.ssh/icloud-ssh-agent.sock
```

To sign Git commits, add the public key as a signing key with your Git host too. Put the `export` line in your shell profile so `ssh-keygen`, which Git uses to sign, can find the agent. Point Git at the public key file: the agent holds the private half.

```sh
export SSH_AUTH_SOCK="$HOME/.ssh/icloud-ssh-agent.sock"

icloud-ssh-agent public-key work > ~/.ssh/work.pub
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/work.pub
git config --global commit.gpgsign true
```

The same file picks which key a host gets in `~/.ssh/config`:

```sshconfig
Host github.com
  IdentityFile ~/.ssh/work.pub
  IdentitiesOnly yes
```

### Signing policy

Each key has its own policy. By default, the agent allows signatures in the `git` namespace and prompts for SSH logins and other `ssh-keygen -Y sign` namespaces.

| Purpose | What it covers | Default |
| --- | --- | --- |
| `ssh` | SSH logins | `prompt` |
| `git` | SSH signatures in the `git` namespace | `allow` |
| `sign` | SSH signatures in other namespaces | `prompt` |

Use `allow` to sign immediately, `prompt` to ask each time, `prompt-5m` to reuse approval for the same key and purpose for five minutes, or `deny` to refuse. The agent also refuses unlisted purposes and requests it can't classify.

When an SSH client sends a session binding, the agent checks login requests against that session. It looks up the host key in `known_hosts` for the prompt and falls back to the key's fingerprint if there's no match. Connections marked as forwarded in a session binding require a fresh approval for any permitted signature. With forwarding that doesn't send a binding, the agent applies the usual policy. Under launchd, every signing decision goes to the macOS unified log. Run `icloud-ssh-agent logs` to see the last day, `logs -f` to follow, or `logs --last 2h` for a different window. In Console.app, filter on the subsystem `li.lds.icloud-ssh-agent`.

### Manage keys

```sh
icloud-ssh-agent list
icloud-ssh-agent import work-existing ~/.ssh/id_ed25519
icloud-ssh-agent set-policy work git=allow,ssh=prompt-5m
(umask 077; icloud-ssh-agent export work > work.pem)
```

You can pass `--policy` to `generate` or `import`. Generation creates an Ed25519 key. Import accepts OpenSSH or PEM private keys (Ed25519, ECDSA, or RSA), prompts if the key is encrypted, and leaves the source file in place. Use `-` as the filename to read from stdin.

Changing a policy or exporting a key requires approval. Use a new filename for the export. `icloud-ssh-agent delete work` removes the key from iCloud Keychain and syncs that deletion to your other devices. `icloud-ssh-agent uninstall` removes the login item and leaves your keys in iCloud Keychain.

## Build from source

Run `TOOL=age-plugin-icloud ./scripts/sign.sh` or `TOOL=icloud-ssh-agent ./scripts/sign.sh` to build an app with your Apple Development signing identity. Building `icloud-ssh-agent` needs Xcode or its command line tools, because it uses cgo for the unified log. You'll need a provisioning profile for the matching bundle ID (`li.lds.age-plugin-icloud` or `li.lds.icloud-ssh-agent`).

With Developer ID and notarization credentials configured, run `./scripts/dist.sh` with the same `TOOL` to sign, notarize, and zip the app. The release workflow builds each tool from its own version tags.
