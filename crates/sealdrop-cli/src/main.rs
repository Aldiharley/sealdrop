//! sealdrop command-line tool.
//!
//! Exit codes: 0 success; 1 any other failure; 2 verification failed or the timed-release
//! window has expired; 3 refused by policy.
//!
//! Everything for stdout goes through `out!`, never `println!`: a reader that goes away
//! (`sealdrop recipient | head -1`) must end the program quietly with exit 0, not panic
//! with exit 101.

/// `println!` that returns from the enclosing function (with `StdoutClosed`) instead of
/// panicking when stdout is a closed pipe.
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::print_line(format_args!($($arg)*))?
    };
}

mod commands;

use std::fmt;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sealdrop_core::keys::KeyStore;
use sealdrop_core::Error;

#[derive(Parser)]
#[command(
    name = "sealdrop",
    bin_name = "sealdrop",
    version,
    about = "Send sensitive files with standard encryption, a signed delivery record, and optional timed release.",
    after_help = "Exit codes: 0 success, 1 error, 2 verification failed or package expired, 3 refused by policy.\n\
                  Set SEALDROP_HOME to use a different key-store folder."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create your identity (age key pair + minisign signing key)
    Keygen {
        /// Replace an existing identity (the old keys are lost)
        #[arg(long)]
        force: bool,
    },
    /// Print your public recipient string and signer key
    Recipient,
    /// Encrypt a file or folder to recipients or a generated passphrase
    Seal(commands::seal::Args),
    /// Check the signed manifest and ciphertext hash without decrypting
    Verify(commands::verify::Args),
    /// Verify, decrypt and safely extract a package
    Open(commands::open::Args),
    /// Fetch or verify timed-release receipts
    Receipt {
        #[command(subcommand)]
        cmd: commands::receipt::Cmd,
    },
    /// Manage trusted signers
    Trust {
        #[command(subcommand)]
        cmd: commands::trust::Cmd,
    },
}

/// The reader of stdout has gone away; the command stops and the process exits 0 quietly.
#[derive(Debug)]
pub(crate) struct StdoutClosed;

impl fmt::Display for StdoutClosed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("stdout was closed")
    }
}

impl std::error::Error for StdoutClosed {}

/// Writes one line; a broken pipe becomes `StdoutClosed`, any other failure an error.
pub(crate) fn write_line<W: Write>(w: &mut W, args: fmt::Arguments<'_>) -> anyhow::Result<()> {
    match writeln!(w, "{args}").and_then(|()| w.flush()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Err(StdoutClosed.into()),
        Err(e) => Err(e.into()),
    }
}

pub(crate) fn print_line(args: fmt::Arguments<'_>) -> anyhow::Result<()> {
    write_line(&mut std::io::stdout().lock(), args)
}

/// True when the command stopped because stdout was closed: exit 0, print nothing.
pub(crate) fn is_quiet_exit(e: &anyhow::Error) -> bool {
    e.downcast_ref::<StdoutClosed>().is_some()
}

pub(crate) fn store() -> KeyStore {
    match std::env::var_os("SEALDROP_HOME") {
        Some(p) => KeyStore::open(PathBuf::from(p)),
        None => KeyStore::open(KeyStore::default_dir()),
    }
}

/// Finds the sealdrop error that decides the exit code, looking through the error chain and
/// through the `io::Error` that age uses to carry a failure raised while decrypting (an
/// expired timed-release package surfaces that way).
fn classify<'a>(e: &'a (dyn std::error::Error + 'static)) -> Option<&'a Error> {
    if let Some(err) = e.downcast_ref::<Error>() {
        if let Error::Decrypt(age::DecryptError::Io(io)) = err {
            if let Some(inner) = io.get_ref().and_then(|i| classify(i)) {
                return Some(inner);
            }
        }
        return Some(err);
    }
    if let Some(io) = e.downcast_ref::<std::io::Error>() {
        if let Some(inner) = io.get_ref().and_then(|i| classify(i)) {
            return Some(inner);
        }
    }
    None
}

pub(crate) fn find_error(e: &anyhow::Error) -> Option<&Error> {
    e.chain().find_map(classify)
}

pub(crate) fn exit_code_for(e: &anyhow::Error) -> u8 {
    match find_error(e) {
        Some(Error::Verify(_)) | Some(Error::ReleaseExpired) => 2,
        Some(Error::Policy(_)) => 3,
        _ => 1,
    }
}

fn message_for(e: &anyhow::Error) -> String {
    match find_error(e) {
        Some(Error::ReleaseExpired) => {
            "this package has expired at the release service and can no longer be opened".into()
        }
        _ => format!("{e:#}"),
    }
}

fn main() -> ExitCode {
    // clap exits 2 on usage errors by default, but 2 means "verification failed" here.
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            return match e.kind() {
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
                    ExitCode::SUCCESS
                }
                _ => ExitCode::from(1),
            };
        }
    };
    let r = match cli.cmd {
        Cmd::Keygen { force } => commands::keygen::run(force),
        Cmd::Recipient => commands::recipient::run(),
        Cmd::Seal(a) => commands::seal::run(a),
        Cmd::Verify(a) => commands::verify::run(a),
        Cmd::Open(a) => commands::open::run(a),
        Cmd::Receipt { cmd } => commands::receipt::run(cmd),
        Cmd::Trust { cmd } => commands::trust::run(cmd),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if is_quiet_exit(&e) => ExitCode::SUCCESS,
        Err(e) => {
            // Error text can quote file-controlled values; never let them drive the terminal.
            eprintln!("error: {}", commands::sanitize(&message_for(&e)));
            ExitCode::from(exit_code_for(&e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sealdrop_core::policy::PolicyError;

    #[test]
    fn exit_codes() {
        let verify = anyhow::Error::new(Error::Verify("x".into()));
        assert_eq!(exit_code_for(&verify), 2);
        let policy = anyhow::Error::new(Error::Policy(PolicyError::NoRecipients));
        assert_eq!(exit_code_for(&policy), 3);
        assert_eq!(exit_code_for(&anyhow::anyhow!("other")), 1);
        assert_eq!(
            exit_code_for(&anyhow::Error::new(Error::Other("x".into()))),
            1
        );
        // With added context the underlying error still decides.
        let ctx = anyhow::Error::new(Error::Policy(PolicyError::NoRecipients)).context("hint");
        assert_eq!(exit_code_for(&ctx), 3);
    }

    /// A writer whose reader has gone away, like a pipe into `head -1` after one line.
    struct ClosedPipe;
    impl Write for ClosedPipe {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct Full;
    impl Write for Full {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("disk full"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn closed_stdout_is_a_quiet_exit_not_a_panic() {
        let e = write_line(&mut ClosedPipe, format_args!("age1...")).unwrap_err();
        assert!(is_quiet_exit(&e));
        // Even with context added on the way up.
        assert!(is_quiet_exit(&e.context("printing")));
        // Other write failures stay errors with exit 1.
        let e = write_line(&mut Full, format_args!("x")).unwrap_err();
        assert!(!is_quiet_exit(&e));
        assert_eq!(exit_code_for(&e), 1);
        let mut buf = Vec::new();
        write_line(&mut buf, format_args!("a {}", 1)).unwrap();
        assert_eq!(buf, b"a 1\n");
    }

    #[test]
    fn expiry_wrapped_in_decrypt_io_exits_2() {
        let io = std::io::Error::other(Error::ReleaseExpired);
        let wrapped = anyhow::Error::new(Error::Decrypt(age::DecryptError::Io(io)));
        assert_eq!(exit_code_for(&wrapped), 2);
        assert!(message_for(&wrapped).contains("expired"));
        let io = std::io::Error::other("disk");
        let other = anyhow::Error::new(Error::Decrypt(age::DecryptError::Io(io)));
        assert_eq!(exit_code_for(&other), 1);
    }
}
