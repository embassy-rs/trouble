## 📦 Cargo.lock Policy

This repository contains a mix of libraries, examples, and test binaries. To ensure clarity and reproducibility, we follow a nuanced approach to `Cargo.lock` inclusion:

### ✅ What we commit
We include `Cargo.lock` files **only** for test binaries that are executed in CI:

- [`examples/tests/Cargo.lock`](examples/tests/Cargo.lock)
- [`host/Cargo.lock`](host/Cargo.lock) — used by `host/tests`

These lockfiles ensure reproducible CI runs and provide a stable dependency baseline for contributors running tests locally.

### ❌ What we ignore
We do **not** commit `Cargo.lock` for:

- The root crate (which is a library)
- Example applications (which are not CI-tested and often target MCU hardware)

This aligns with [Cargo's official guidance](https://doc.rust-lang.org/cargo/guide/cargo-toml-vs-cargo-lock.html), which recommends:

> *“Cargo.lock is not used for libraries to avoid locking dependencies for downstream users.”*

### 🧠 Why this matters
- **Libraries** should remain flexible for downstream consumers.
- **Examples** are illustrative and not CI-tested; locking them would add unnecessary maintenance burden.
- **Test binaries** benefit from locked dependencies to ensure consistent CI behavior and easier debugging.

### 🛠 `.gitignore` setup
Our root `.gitignore` reflects this policy:

```gitignore
# Ignore lock files, except where we don't.
Cargo.lock
!/examples/tests/Cargo.lock
!/host/Cargo.lock
```

<!--
Text from Copilot discussion, 16-Oct-25
-->
