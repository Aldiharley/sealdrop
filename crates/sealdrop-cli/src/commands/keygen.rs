use sealdrop_core::keys::IdentityKind;

pub fn run(force: bool, pq: bool) -> anyhow::Result<()> {
    let ks = crate::store();
    let kind = if pq {
        IdentityKind::Pq
    } else {
        IdentityKind::X25519
    };
    let info = ks.generate(force, kind)?;
    out!("{}", info.recipient);
    out!("{}", info.signer);
    eprintln!(
        "identity written to {} (kind: {})",
        ks.dir().display(),
        info.kind
    );
    if pq {
        eprintln!("post-quantum identity: senders need sealdrop 0.3 or age 1.3 or newer");
    }
    eprintln!("share the first line (your recipient) with senders; the second is your signer key");
    Ok(())
}
