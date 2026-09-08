//! Kavach-NPU command-line control-plane skeleton.

use std::env;

fn main() {
    match env::args().nth(1).as_deref() {
        Some("status") => {
            unimplemented!("`kavach status` is not implemented in the scaffolding phase")
        }
        Some("tripwire") => {
            unimplemented!("`kavach tripwire` is not implemented in the scaffolding phase")
        }
        Some("wsl") => unimplemented!("`kavach wsl` is not implemented in the scaffolding phase"),
        _ => {
            eprintln!("usage: kavach-npu <status|tripwire|wsl>");
            std::process::exit(2);
        }
    }
}
