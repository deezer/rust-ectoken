# rust-ectoken

![CI](https://github.com/deezer/rust-ectoken/workflows/CI/badge.svg)
[![crates.io](https://img.shields.io/crates/v/ectoken.svg)](https://crates.io/crates/ectoken)
[![Docs](https://docs.rs/ectoken/badge.svg)](https://docs.rs/ec_token)

Token Generator for Edgecast Token-Based Authentication from Verizon Digital Media Services

Written against Rust 2018. (Minimum rustc version 1.34.0)

To build and install the test utility, simply run `cargo build --release`

# Usage
To use rust-ectoken, add the following to your Cargo.toml:

```toml
[dependencies]
ectoken = "^0.2"
```

and the following to your crate root:

```rust
extern crate ectoken;
```

Command-line usage for encrypting and decrypting is as follows:

```
To Encrypt:
  ec_encrypt <key> <text>
or:
  ec_encrypt encrypt <key> <text>

To Decrypt:
  ec_encrypt decrypt <key> <text>
```

Please have a look to generated and tested doc for more information.
