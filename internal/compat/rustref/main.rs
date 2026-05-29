//! Reference binary emitting iroh-base values for cross-implementation parity
//! checks against the go-iroh CLI. Each subcommand mirrors an `iroh` CLI
//! command and prints the same canonical output.

use std::str::FromStr;

use iroh_base::{PublicKey, SecretKey};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let out = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["key", "public", hex] => {
            let bytes = decode32(hex);
            SecretKey::from_bytes(&bytes).public().to_string()
        }
        ["key", "z32", key] => PublicKey::from_str(key).unwrap().to_z32(),
        ["sign", hex, msg] => {
            let bytes = decode32(hex);
            let sig = SecretKey::from_bytes(&bytes).sign(msg.as_bytes());
            data_encoding::HEXLOWER.encode(&sig.to_bytes())
        }
        _ => {
            eprintln!("rustref: unknown args {args:?}");
            std::process::exit(2);
        }
    };
    println!("{out}");
}

fn decode32(hex: &str) -> [u8; 32] {
    let v = data_encoding::HEXLOWER.decode(hex.as_bytes()).expect("hex");
    let mut b = [0u8; 32];
    b.copy_from_slice(&v);
    b
}
