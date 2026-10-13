pub fn run(force: bool) -> anyhow::Result<()> {
    let ks = crate::store();
    let info = ks.generate(force)?;
    println!("{}", info.recipient);
    println!("{}", info.signer);
    eprintln!("identity written to {}", ks.dir().display());
    eprintln!("share the first line (your recipient) with senders; the second is your signer key");
    Ok(())
}
