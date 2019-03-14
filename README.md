# rust-ectoken
Token Generator for Edgecast Token-Based Authentication from Verizon Digital Media Services

Written against Rust 2018.

To build and install the test utility, simply run `cargo build --release`

# Usage
To use rust-ectoken, add the following to your Cargo.toml:

```toml
[dependencies]
rust-ectoken = "^0.1"
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
