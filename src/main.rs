//! sshprivscan - Scan a system for SSH private keys and check them
//!
//! Checks:
//! * Passphrase: If key can be used to generate public key, without
//!   need of passphrase, then it does not have one. Complain.

// SPDX-License-Identifier:  GPL-3.0-only

#![warn(missing_docs)]

use anyhow::Result;
use clap::Parser;
use jwalk::WalkDir;
use log::{debug, info, trace, warn};
use rayon::prelude::*;
use std::{fs, process::Command};

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
    /// When [Args::fullscan] is set, the default here changes to /.
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

/// And off we go, check the system
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

    // Store candidates to look at
    let mut entries: Vec<String> = Vec::new();

    trace!("Walking down {} now", &args.startdir);
    // Collect candidates
    for entry in WalkDir::new(&args.startdir).sort(true).skip_hidden(false) {
        let fpath = &entry.as_ref().unwrap().path();
        // Check their size, SSH keys aren't that large. A 16k RSA one
        // is slightly more than 12000 bytes
        let size = if fpath.exists() && fpath.is_file() {
            fs::metadata(fpath)?.len()
        } else {
            65535
        };
        // No need to check directories or files too large
        if fpath.is_dir()
            || size >= 13000
            || fpath.starts_with("/proc")
            || fpath.starts_with("/dev")
            || fpath.starts_with("/sys")
            || fpath.starts_with("/run")
        {
            continue;
        }
        // Store for future use
        entries.push(entry.unwrap().path().to_string_lossy().to_string());
    }

    // And now, check them all, using rayon to go parallel
    entries.par_iter().for_each(move |entry| {
        debug!("P: {:#?}", entry);
        // Read file contents
        let contents = fs::read_to_string(&entry).unwrap_or_else(|_| "Failed to read".to_string());

        // If this string is contained, it MAY be a candidate
        if contents.contains(&"PRIVATE KEY") {
            debug!(
                "Possible SSH or RSA Private key found, checking ({:?}).",
                entry
            );

            // Call it with a fake passphrase
            let output = Command::new("/usr/bin/ssh-keygen")
                .current_dir("/")
                .arg("-P lalaTESTkabChu9bledsshprivscan")
                .arg("-y")
                .arg("-f")
                .arg(&entry)
                .output()
                .unwrap();
            // If this is successful, the key is without passphrase.
            if output.status.success() {
                // Lets parse the key, so we can hand out some more information about it
                let pubkey =
                    sshkeys::PublicKey::from_string(&String::from_utf8_lossy(&output.stdout))
                        .unwrap();
                println!(
                    "Key without passphrase: {:?}, Fingerprint: {}, Size: {}bits, Typ: {}",
                    &entry,
                    pubkey.fingerprint(),
                    pubkey.bits(),
                    pubkey.key_type
                );
            } else {
                debug!("Not a parseable SSH key / SSH Key with passphrase");
            }
        }
    });

    Ok(())
}
