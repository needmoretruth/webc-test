//! `weft` — the single-binary toolchain, earliest skeleton.
//!
//! The decided design's toolchain is one binary (`weft fmt|check|test|build` +
//! LSP). This skeleton wires the three subcommands the compiler can already back:
//!
//! - `weft check <file.weft>` — compile and report success or the typed diagnostic;
//! - `weft build <file.weft>` — compile and print the interface manifest (JSON);
//! - `weft wat   <file.weft>` — compile and print the reference WAT.
//!
//! `fmt`, `test`, and the LSP are future work over the same front end. No path
//! panics; a bad file or a compile error is a clean non-zero exit.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<String, String> {
    let command = args.get(1).map(String::as_str);
    let path = args.get(2);
    match (command, path) {
        (Some("check"), Some(path)) => {
            let out = compile(path)?;
            Ok(format!(
                "ok: component `{}` — {} bytes wasm, {} footprint key(s)",
                out.manifest.component,
                out.wasm.len(),
                out.footprint.len()
            ))
        }
        (Some("build"), Some(path)) => Ok(compile(path)?.manifest.to_json()),
        (Some("wat"), Some(path)) => Ok(compile(path)?.wat),
        _ => Err("usage: weft <check|build|wat> <file.weft>".to_string()),
    }
}

fn compile(path: &str) -> Result<webc_weft::Compiled, String> {
    let src = std::fs::read_to_string(path).map_err(|err| format!("cannot read {path}: {err}"))?;
    webc_weft::compile(&src).map_err(|err| format!("{path}: {err}"))
}
