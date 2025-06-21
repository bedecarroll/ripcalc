use clap_complete::{generate_to, shells};
use clap_mangen::Man;
use std::fs;
use std::io::Error;
use std::path::PathBuf;

include!("src/cli.rs");

fn main() -> Result<(), Error> {
    let out_dir = match std::env::var_os("OUT_DIR") {
        None => return Ok(()),
        Some(out_dir) => out_dir,
    };

    let mut cmd = build_cli();

    // Generate manpage
    let man_dir = PathBuf::from(&out_dir).join("man");
    fs::create_dir_all(&man_dir)?;

    let man = Man::new(cmd.clone());
    let mut buffer: Vec<u8> = vec![];
    man.render(&mut buffer)?;

    fs::write(man_dir.join("ripcalc.1"), buffer)?;

    // Generate shell completions
    let comp_dir = PathBuf::from(&out_dir).join("completions");
    fs::create_dir_all(&comp_dir)?;

    // Generate completions for all major shells
    generate_to(shells::Bash, &mut cmd, "ripcalc", &comp_dir)?;
    generate_to(shells::Zsh, &mut cmd, "ripcalc", &comp_dir)?;
    generate_to(shells::Fish, &mut cmd, "ripcalc", &comp_dir)?;
    generate_to(shells::PowerShell, &mut cmd, "ripcalc", &comp_dir)?;

    println!("cargo:rerun-if-changed=src/cli.rs");
    println!("cargo:rerun-if-changed=build.rs");

    Ok(())
}
