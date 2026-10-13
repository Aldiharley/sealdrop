use clap::Subcommand;

#[derive(Subcommand)]
pub enum Cmd {
    /// Trust a signer: packages signed by this key verify without --signer
    Add {
        /// A short name (letters, digits, - and _)
        name: String,
        /// The signer key, as printed by `sealdrop recipient` (second line)
        key: String,
    },
    /// List trusted signers
    List,
    /// Stop trusting a signer
    Remove {
        /// Name given to `trust add`
        name: String,
    },
}

pub fn run(cmd: Cmd) -> anyhow::Result<()> {
    let ks = crate::store();
    match cmd {
        Cmd::Add { name, key } => {
            ks.add_trusted(&name, &key)?;
            println!("trusted {name}");
        }
        Cmd::List => {
            for (n, pk) in ks.trusted()? {
                println!("{n}\t{}", pk.to_base64());
            }
        }
        Cmd::Remove { name } => {
            ks.remove_trusted(&name)?;
            println!("removed {name}");
        }
    }
    Ok(())
}
