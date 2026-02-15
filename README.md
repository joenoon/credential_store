# CredentialStore

Per-environment encrypted credential storage for Elixir applications. Secrets live in a single JSON file with each environment section encrypted independently via AES-256-CBC. No decrypted data ever touches disk.

## Installation

Add `credential_store` to your dependencies:

```elixir
def deps do
  [
    {:credential_store, github: "joenoon/credential_store"}
  ]
end
```

## Setup

Set `CREDENTIAL_STORE_KEY` to any secret string (a UUID works well). Each environment can use a different key.

```bash
export CREDENTIAL_STORE_KEY="your-secret-key-here"
```

## Interactive Editor

Manage secrets through the built-in Mix task:

```bash
CREDENTIAL_STORE_KEY=my-key mix credential_store --env dev
```

```
CredentialStore (env: dev)
──────────────────────────────

  (no secrets yet — use [a]dd to create one)

Commands: [a]dd  [e]dit  [d]elete  [v]iew  [s]ave & exit  [q]uit without saving
```

The editor decrypts secrets into memory, lets you modify them, and re-encrypts on save. Values are masked in the listing and only revealed with the `[v]iew` command.

If `CREDENTIAL_STORE_KEY` doesn't match the key used to encrypt a section, the editor will refuse to open it — preventing silent data corruption.

## Runtime Usage

Load secrets at application startup (e.g. in `config/runtime.exs`):

```elixir
secrets = CredentialStore.load_secrets(:my_app, env: config_env())
```

Then fetch individual values:

```elixir
CredentialStore.get(secrets, "LLM_API_KEY")
#=> "sk-ant-..."

CredentialStore.get!(secrets, "DB_PASSWORD")
#=> raises KeyError if not found

# Nested paths
CredentialStore.get(secrets, ["services", "stripe", "secret_key"])
```

## How It Works

Secrets are stored in `priv/secrets.enc.json`:

```json
{
  "dev": {
    "_cs_check": "...",
    "LLM_API_KEY": "...",
    "DB_PASSWORD": "..."
  },
  "prod": {
    "_cs_check": "...",
    "LLM_API_KEY": "..."
  }
}
```

- **Keys are plaintext**, values are AES-256-CBC encrypted and Base64-encoded
- Each environment section is encrypted with its own `CREDENTIAL_STORE_KEY`
- A `_cs_check` sentinel verifies the correct key is being used on load
- The encrypted file is safe to commit to version control

## API

| Function | Description |
|----------|-------------|
| `CredentialStore.load_secrets(app, env: env)` | Load and decrypt secrets for an OTP app at runtime |
| `CredentialStore.get(secrets, key_or_path)` | Fetch a value, returns `nil` if missing |
| `CredentialStore.get!(secrets, key_or_path)` | Fetch a value, raises if missing |
| `CredentialStore.load_section(env)` | Load a section directly (used by the editor) |
| `CredentialStore.save_section(env, map)` | Encrypt and save a section (used by the editor) |

## License

MIT
