# Key Store

Reads credentials from **Azure Key Vault**, **AWS Secrets Manager**, **1Password
Connect** and **Bitwarden Secrets Manager**, and publishes them as variables that
channels can use — `${keystore.name}` in any connector field, and a script API
for transformers and deploy scripts.

The point is that a credential stops living in your channel XML. A channel says
`${keystore.partnerApiToken}`; which vault that comes from, under what name, and
which field of it, is configuration you can change without touching a channel.
Rotate the secret in the vault and a running engine picks it up on its next
refresh — no redeploy, no restart.

```
./plugins/oie-key-store/build.sh
cp plugins/oie-key-store/dist/keystore-0.1.0.zip extensions/
docker compose up -d --force-recreate engine
./scripts/oie-check-extensions.sh "Key Store"
```

Then open **Key Store** in the web administrator: add a vault, bind a secret to a
name, and paste the placeholder it gives you into a connector field.

## Using a secret

Three ways, and they read the same values.

**In a connector field** — anywhere the engine does `${...}` replacement, which
is most of them: an HTTP Sender's URL, username and password; a Database Writer's
URL and password; an SFTP sender's password or passphrase.

```
${keystore.partnerApiToken}
```

**In a script**, when you want the value in JavaScript:

```javascript
var KeyStore = org.openintegrationengine.plugins.keystore.Secrets;

var token = KeyStore.get('partnerApiToken');           // null if unavailable
var token = KeyStore.get('partnerApiToken', 'dev-key'); // or a fallback
var token = KeyStore.require('partnerApiToken');       // or throw, naming it
```

`require` is the one to use in a **deploy script**. A channel that cannot get its
credential should fail to deploy, loudly, rather than start and authenticate as
nobody.

**From the global map**, which is where the values actually live:

```javascript
globalMap.get('keystore').get('partnerApiToken');
```

### One place `${...}` does not work

The **global deploy script** — the server-wide one, not a channel's. On a
"Redeploy All" the engine clears the global map, and although this plugin puts
the values straight back, the global deploy script runs in the gap. Use
`Secrets.get()` there; it reads what the plugin is holding and never looks at the
global map, so it is unaffected.

Channel connector fields and channel deploy scripts are fine: both run after the
plugin has restored the map.

## Vaults

Add one per account you read from. Several are allowed on purpose — a partner's
Key Vault beside your own, or separate AWS accounts for two payers — because
collapsing those into one credential is how a production key ends up in a test
instance.

**Test** before saving. It authenticates and reports what the identity can
actually see, including the most common half-working state: "authenticated, but
this identity cannot list secrets", which is a working setup if you have granted
read on specific secrets, and a missing access policy if you have not.

### Azure Key Vault

Vault URL is the DNS name from the vault's overview page,
`https://contoso.vault.azure.net`. Sign in with:

| Mode | Needs |
| --- | --- |
| Client secret | Tenant ID, client ID and the secret. Stored here, encrypted. |
| Managed identity | The engine running on Azure with an identity assigned. Nothing stored. Leave the client ID empty for the system-assigned identity. |
| Workload identity | AKS, with `AZURE_FEDERATED_TOKEN_FILE` set by the workload identity webhook. Nothing stored. |

The identity needs **Get** on secrets, through an access policy or the *Key Vault
Secrets User* role. List is separate and optional.

A binding's secret is just the name, `partner-api-token`. The version field takes
a version id; empty means the current one.

### AWS Secrets Manager

Region is required. Sign in with:

| Mode | Needs |
| --- | --- |
| Access key | An access key ID and secret. Stored here, encrypted. |
| Environment variables | `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in the engine's environment. |
| Instance or task role | ECS task role, or the EC2 instance role over IMDSv2. Nothing stored. |
| IAM role for service account | EKS, with `AWS_WEB_IDENTITY_TOKEN_FILE` and `AWS_ROLE_ARN`. Nothing stored. |

**Assume role ARN** (under *More options*) is assumed after the credential above
— how one engine reads a secret owned by another account without holding that
account's keys.

The policy needs `secretsmanager:GetSecretValue`, and `kms:Decrypt` on the key if
the secret uses a customer-managed one. A binding's secret is the name or the
full ARN. The version field takes a version id or a stage such as `AWSPREVIOUS`;
empty means `AWSCURRENT`.

Secrets Manager's console writes key/value secrets as a single JSON document, so
a database credential is usually one secret containing `username` and `password`
rather than two secrets. Use **Field within the secret** to pick one out:

| Binding | Secret | Field | Resolves to |
| --- | --- | --- | --- |
| `dbUser` | `prod/db/app` | `username` | the username |
| `dbPassword` | `prod/db/app` | `password` | the password |

### 1Password Connect

This talks to a **Connect server** you run, not to 1Password.com. Connect is the
only 1Password interface a long-running server process can use without a CLI on
the host — service accounts go through the SDK or `op`, and installing a binary
into the engine image is a worse dependency than an HTTP call.

Enter the Connect server URL and the access token issued with its credentials
file. The token only reaches the vaults it was granted, and the Test button lists
them.

A secret is a path, because a 1Password item has fields and you have to say which:

```
Production/Partner API              the item's password
Production/Partner API/api key      a field by its label
op://Production/Partner API/username    a reference pasted as it stands
```

Names or UUIDs both work. With no field named, the item's password is used.

Connect has no per-version read, so leave the version field empty.

### Bitwarden Secrets Manager

Paste a machine account **access token**, complete — including the part after the
colon, which is the key the values are decrypted with. A truncated paste is
caught when you save.

Secrets Manager is zero-knowledge: the API returns every value encrypted, and the
organisation key arrives encrypted under a key derived from your access token. So
unlike the other three, this one does real cryptography — AES-256-CBC with an
HMAC-SHA256 tag, and Bitwarden's `derive_shareable_key` on top. The build checks
that derivation against Bitwarden's own published test vectors, and the plugin
checks it again at startup, because a derivation that is subtly wrong does not
fail cleanly: it produces a different key, and a wrong password handed to a
channel is much worse than a refusal.

A binding's secret is the secret's key, or its UUID. Looking one up by key costs
a list and a decryption of every key in it — the server cannot filter on them
because they are ciphertext — so the result is cached. If two projects use the
same key, bind by UUID; the plugin refuses to guess.

For the EU cloud, set the identity and API URLs to `https://identity.bitwarden.eu`
and `https://api.bitwarden.eu` under *More options*. Secrets Manager has no
versions, so leave the version field empty.

## Settings

**Variable prefix** — `keystore` by default, so secrets are `${keystore.name}`.
Changing it means editing every connector field that uses one; the old prefix
stops resolving immediately, which is deliberate, because a prefix that quietly
kept working would never be refreshed again.

**Read every** — 900 seconds by default, minimum 60. This is how long a rotated
secret takes to reach running channels. A change takes effect on restart.

**If a vault cannot be reached** — keep serving the last value that was read. On
by default: the credential has not changed, only your ability to re-read it, so
channels keep working through a vault outage. Switch it off where a revoked
secret must stop being usable within one refresh interval, and accept that a
vault outage then stops the channels that depend on it.

**Event log** — writes a warning into the engine's own event log when a secret
cannot be read at all, where alerts can see it. Stale values are logged to the
server log but do not raise an event: nothing has stopped working, and an event
every refresh for a vault that is down all afternoon buries the ones that matter.

## Where the values live, and who can see them

In the engine's **global map**, in memory, under one key holding a map of name to
value.

That is not a free choice. `TemplateValueReplacer` builds its context from
exactly two places — the configuration map and the global map — and everything a
connector field can resolve comes from one of them. The configuration map is
persisted to the `configuration` table in clear text and displayed in full on a
settings page in the Administrator, so putting vault secrets there would mean
copying every credential out of the vault and into the database, which is most of
the reason for having a vault. The global map is memory only, is never written to
disk by the engine, and is rebuilt from the vaults on every start.

**The trade this leaves is real: anything that can read the global map can read
these values, which includes any JavaScript in any channel on this engine.** This
plugin narrows who can see a credential down to *the engine*, not down to a
channel. If a channel author must not see a credential, this is not the control
that achieves it.

What the plugin does guarantee:

- **Vault credentials** — the client secret, access key, Connect token or
  Bitwarden access token — are encrypted with the engine's own encryptor before
  being stored, so a database dump does not hand over access to your vaults. The
  encryptor is keyed from `appdata/keystore.jks`, which is a different volume
  from the database in this stack. **Back up both**, or a restore leaves you
  re-entering every credential.
- **No API response carries a secret value or a stored credential.** The console
  shows the name, the vault, whether the last read worked and how many characters
  the value has — enough to spot a truncated paste without putting the credential
  on a screen.
- **Nothing is logged.** Failures name the variable and the secret, never the
  value.
- A credential field left blank when editing a vault **keeps the stored one**.
  The console is never sent a credential, so it has nothing to send back.

## Failure behaviour

A binding that cannot be read is **absent** from the published map, not present
and empty. An empty password looks like a configured one and would be sent; a
missing key leaves the literal `${keystore.name}` in the field, which fails
loudly and says exactly what did not resolve.

States on the Key Store page:

| State | Meaning |
| --- | --- |
| OK | Read from the vault on the last pass. |
| Stale | The last read failed; the previously read value is still being served. |
| Not available | No value. The variable is not published. |
| No vault | The vault it names is switched off or has been deleted. |
| Disabled | Switched off in the binding editor. |

Deleting a vault does **not** delete the bindings that use it — a vault removed
by mistake is one edit away from being restored, whereas cascading the delete has
no undo. The response says how many bindings stopped resolving.

## What it depends on

Nothing that is not already in the engine. All four vaults are reached over their
documented HTTPS APIs with the JDK's own `HttpClient`, and the only library used
beyond the engine's controllers is Jackson, which the engine already loads from
`server-lib`. No third-party jars are bundled and nothing extra is loaded into
the engine's JVM.

AWS requests are signed with SigV4 written out here rather than taken from an
SDK. The engine ships AWS SDK 2.15.28 for S3 and KMS but not its Secrets Manager
module, and adding a current module beside a 2020 core is the sort of split that
works right up until a shared class changes underneath it. SigV4 has not changed
since 2012 and is about eighty lines.

## Notes for the curious

**The plugin is both a `ServicePlugin` and a `ChannelPlugin`.** The second is not
decoration: deploying every channel calls the engine's `clearGlobalMap()` between
the undeploy and the deploy, so without a deploy hook every secret would vanish
on a "Redeploy All" and not come back until the next scheduled refresh — minutes
of channels authenticating with the literal text `${keystore.name}`. The deploy
hooks put the values back from memory, contacting no vault.

One consequence of implementing both interfaces: the extension controller adds
the object to its server-plugin list once per interface it matches and then
starts every entry, so `init`, `start` and `stop` are each called twice. They are
guarded. Without the guard there would be two refresh schedulers, doubling the
traffic to every vault and leaking one at shutdown.

**Settings live in the `configuration` table**, through
`ConfigurationController.saveProperty`, one row per vault and per binding — not
one row holding all of them. Deleting is then a `removeProperty` instead of a
read-modify-write of a single blob, so two administrators editing different rows
cannot silently drop each other's work. It also has to be the database rather
than a file: this image resets `conf/` and `extensions/` from pristine copies on
every boot.
