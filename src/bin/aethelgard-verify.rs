use aethelgard_mesh::crypto::SignedExecution;
use std::{env, fs, process::ExitCode};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: aethelgard-verify <trusted-public-key-hex> <signed-record.json>");
        return ExitCode::from(2);
    }

    let trusted_key = &args[1];
    let contents = match fs::read(&args[2]) {
        Ok(contents) => contents,
        Err(error) => {
            eprintln!("Could not read signed record: {error}");
            return ExitCode::from(2);
        }
    };

    let record: SignedExecution = match serde_json::from_slice(&contents) {
        Ok(record) => record,
        Err(error) => {
            eprintln!("Invalid signed-record JSON: {error}");
            return ExitCode::from(2);
        }
    };

    if record.verify_with_trusted_key(trusted_key) {
        println!("VALID: signature and manifest digest match the pinned public key.");
        ExitCode::SUCCESS
    } else {
        eprintln!("INVALID: signature, digest, or trusted public key did not match.");
        ExitCode::FAILURE
    }
}
