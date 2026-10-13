pub fn run() -> anyhow::Result<()> {
    let ks = crate::store();
    println!("{}", ks.recipient_string()?);
    println!("{}", ks.signing_public_string()?);
    Ok(())
}
