# l4f-accounts

Users, roles, scopes and authentication for [l4f.cc](https://l4f.cc), as a
library: password sign-in with Argon2id, TOTP and recovery codes, passkeys,
SSH-key and device-key sign-in, social sign-in (Discord, Google, Facebook),
email confirmation and password reset, role and user administration, opt-in
settings sync, an end-to-end encrypted vault, and public profiles. It ships its
own `/account` pages for axum hosts and a service layer any server can call.

- [docs/embedding.md](docs/embedding.md): features, what a host must do, calls
  without HTTP.
- [docs/vault-format.md](docs/vault-format.md): the vault's byte layout, pinned
  by `tests/vault_vectors.rs`.
- [CHANGELOG.md](CHANGELOG.md): versions, migrations, breaking changes.

## Tests

```sh
cargo test --all-features                        # database tests skip without a database
cargo clippy --all-targets --all-features
```

The store, service and router tests need a throwaway MariaDB; they pass
vacuously without one. Point `L4F_TEST_DATABASE_URL` at a database the user may
also create `<name>_<hex>` siblings of:

```sh
export L4F_TEST_DATABASE_URL=mysql://l4f:l4f-test-only@127.0.0.1:3399/l4f_test
```

Never at a database with real data: tests create and delete accounts in it.
Each feature set builds on its own (`--no-default-features`, `--features mysql`,
`axum`, `email`, `oauth`); CI-style checks run all of them.
