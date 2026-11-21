# age-plugin-icloud

:warning: *This is mostly vibe coded, and homelab quality code. It has not been deeply security reviewed, and the design does have limitations*

An [age](https://age-encryption.org) plugin that keeps an MLKEM768-X25519 secret in iCloud Keychain. Recipients are ordinary `age1pq1...` public keys, so encryption does not need this plugin.

Limitations:
* Secret is stored in the iCloud keychain, and synced. It is protected to the normal Keychain + Sync levels, the secret is extractable.
* The biometric unlock is enforced by the plugin, not the keychain. The unlock time is stored as an attribute on the secret. The command only changes the access level after Touch ID, but anything granted permission to the keychain item can change it directly.

## Install

macOS only. The plugin is a dummy `.app`, symlink the command in to the .app (required for the needed signing)

Download the zip from [Releases](https://github.com/lstoll/age-plugin-icloud/releases).

```bash
ln -sf /path/to/age-plugin-icloud.app/Contents/MacOS/age-plugin-icloud <somewhere on $PATH>/age-plugin-icloud
```

## Usage

Generate (once, on any signed-in Mac). Default name is `default`. `--access-control` is stored on the item (default `5m`).

```bash
age-plugin-icloud --generate > ~/.age/icloud.txt
age-plugin-icloud --generate --name sops-secret --access-control=everyTime
age-plugin-icloud --generate --name ssh --access-control=none
```

Stdout is the identity pointer plus a commented `age1pq` recipient. The secret is only in Keychain. Reprint later with `--list` (optionally `--name`).

```bash
age-plugin-icloud --list --name work > ~/.age/icloud-work.txt
```

Encrypt with the native recipient (any age 1.3.2+ client, no plugin):

```bash
age -r age1pq1... -o secret.age file
```

Encrypt from the identity file or `-j icloud` (reads the stored public key only):

```bash
age -e -i ~/.age/icloud.txt -o secret.age file
age -e -j icloud -o secret.age file
```

Decrypt on any Mac with that Apple ID (plugin + Keychain).

```bash
age -d -i ~/.age/icloud.txt secret.age
age -d -j icloud secret.age
```

`-j icloud` with an empty identity decrypts with every stored name and encrypts to `default`.

```bash
age-plugin-icloud --list
age-plugin-icloud --list --name work
age-plugin-icloud --delete --name work
```

Change an identity's access control, or print its secret key. Both always ask for Touch ID, whatever the current access control:

```bash
age-plugin-icloud --set-access-control --name work --access-control=everyTime
age-plugin-icloud --export --name work > work.key
```

## icloud-ssh-agent

An SSH agent from the same repo, shipped as its own signed app (`icloud-ssh-agent.app`). Keys live in iCloud Keychain, in a separate access group from the age identities, and sync to every Mac on the Apple ID. The same limitations apply: secrets are extractable, and prompts are enforced by the agent, not by Keychain.

Every signature is checked against the key's policy, based on what is being signed:

| purpose | what | default |
|---|---|---|
| `ssh` | logging in to a host | `prompt` |
| `git` | `git commit`/`tag` signing (`ssh-keygen -Y sign -n git`) | `allow` |
| `sign` | other `ssh-keygen -Y sign` namespaces | `prompt` |

Actions are `allow`, `prompt` (Touch ID every time), `prompt-5m` (Touch ID, then five minutes per key and purpose) and `deny`. Unlisted purposes, and anything the agent can't classify, are denied. Requests through a forwarded agent always prompt. With OpenSSH 8.9+ the prompt names the destination host, from `known_hosts`. Every decision is logged to `~/Library/Logs/icloud-ssh-agent.log`.

```bash
icloud-ssh-agent install                 # login item via SMAppService; prints ssh/git config
icloud-ssh-agent generate work           # or: --policy git=allow,ssh=prompt-5m
icloud-ssh-agent import old ~/.ssh/id_ed25519 --policy ssh=prompt
icloud-ssh-agent list
icloud-ssh-agent public-key work         # authorized_keys line
icloud-ssh-agent set-policy work ssh=prompt,git=allow     # Touch ID
icloud-ssh-agent export work > work.pem                    # Touch ID
icloud-ssh-agent delete work
icloud-ssh-agent status
```

Point ssh at the agent in `~/.ssh/config`:

```
Host *
  IdentityAgent ~/.ssh/icloud-ssh-agent.sock
```

`ssh-keygen` (and so git signing) only reads `SSH_AUTH_SOCK`, so also `export SSH_AUTH_SOCK=~/.ssh/icloud-ssh-agent.sock`. Import leaves the original key file in place.