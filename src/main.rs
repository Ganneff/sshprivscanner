//! sshprivscan - Scan a system for SSH private keys and check them
//!
//! Checks:
//! * Passphrase: If key can be used to generate public key, without
//!   need of passphrase, then it does not have one. Complain.

// SPDX-License-Identifier:  GPL-3.0-only

#![warn(missing_docs)]

use anyhow::Result;
use clap::Parser;
use filemagic::Magic;
use jwalk::WalkDir;
use log::{debug, info, trace, warn};
use std::process::Command;

/// Options
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Scan full set of directories or only only homedirs of existing users?
    ///
    /// If true, we start at the position given by [Args::startdir]
    /// and recursively search private keys.
    ///
    /// If false, we go over a list of existing users and scan their
    /// homedirs only.
    #[clap(short, long)]
    fullscan: bool,

    /// Starting directory
    ///
    /// We start here and recursively try finding SSH private keys.
    ///
    /// When [App::fullscan] is set, the default here changes to /.
    #[clap(
        short,
        long,
        default_value = "/home",
        default_value_if("fullscan", None, Some("/"))
    )]
    startdir: String,

    /// Be verbose, please
    #[clap(flatten)]
    verbose: clap_verbosity_flag::Verbosity,
}

fn main() -> Result<()> {
    let args = Args::parse();
    // We like logging, set loglevel based on -v on commandline
    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .format_timestamp_nanos()
        .format_target(true)
        .init();
    info!("sshprivscan started");
    debug!("Fullscan: {}", args.fullscan);
    debug!("Startdir: {}", args.startdir);

    let cookie = Magic::open(Default::default()).expect("error");
    cookie.load::<String>(&[]).expect("error");

    trace!("Walking down {} now", args.startdir);
    for entry in WalkDir::new(args.startdir).sort(true) {
        let fpath = &entry.as_ref().unwrap().path();
        if let Ok(v) = cookie.file(&entry.unwrap().path()) {
            match v.as_ref() {
                "PEM RSA private key" | "OpenSSH private key" => {
                    debug!("SSH or RSA Private key found, checking ({:?}).", fpath);

                    let output = Command::new("/usr/bin/ssh-keygen")
                        .current_dir("/")
                        .arg("-P lalaTESTkabChu9bledsshprivscan")
                        .arg("-y")
                        .arg("-f")
                        .arg(fpath)
                        .output()?;
                    if output.status.success() {
                        // Only keys we can successfully parse are
                        // important. They do not have the given/any
                        // passphrase
                        let pubkey = sshkeys::PublicKey::from_string(&String::from_utf8_lossy(
                            &output.stdout,
                        ))?;
                        println!(
                            "Key without passphrase: {:?}, Fingerprint: {}, Size: {}bits, Typ: {}",
                            fpath,
                            pubkey.fingerprint(),
                            pubkey.bits(),
                            pubkey.key_type
                        );
                    } else {
                        debug!("Not a parseable SSH key / SSH Key with passphrase");
                    }
                }
                &_ => {}
            };
        }
    }

    Ok(())
}
