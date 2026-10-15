pub fn run() -> anyhow::Result<()> {
    let ks = crate::store();
    out!("{}", ks.recipient_string()?);
    out!("{}", ks.signing_public_string()?);
    out!("kind: {}", ks.identity_kind()?);
    Ok(())
}
