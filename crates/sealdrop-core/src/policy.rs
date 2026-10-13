//! Recipient policy (spec 5.4, 10).

use crate::crypt::Recipient;

pub const ALLOWED_PLUGINS: &[&str] = &["yubikey", "fido2prf", "se", "tpm"];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("no recipients given")]
    NoRecipients,
    #[error("a passphrase cannot be combined with other recipients")]
    PassphraseMustBeAlone,
    #[error("hardware-only recipients need a recovery recipient (or --allow-unrecoverable)")]
    HardwareOnlyNeedsRecovery,
    #[error("plugin `{0}` is not on the allow-list")]
    PluginNotAllowed(String),
}

pub fn plugin_allowed(name: &str) -> bool {
    ALLOWED_PLUGINS.contains(&name)
}

pub fn check_recipients(
    recipients: &[Recipient],
    passphrase_mode: bool,
    allow_unrecoverable: bool,
) -> Result<(), PolicyError> {
    if passphrase_mode {
        return if recipients.is_empty() {
            Ok(())
        } else {
            Err(PolicyError::PassphraseMustBeAlone)
        };
    }
    if recipients.is_empty() {
        return Err(PolicyError::NoRecipients);
    }
    for r in recipients {
        if let Some(name) = r.plugin_name() {
            if !plugin_allowed(&name) {
                return Err(PolicyError::PluginNotAllowed(name));
            }
        }
    }
    let all_hardware = recipients.iter().all(|r| r.plugin_name().is_some());
    if all_hardware && !allow_unrecoverable {
        return Err(PolicyError::HardwareOnlyNeedsRecovery);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypt::Recipient;

    fn x() -> Recipient {
        Recipient::parse(&age::x25519::Identity::generate().to_public().to_string()).unwrap()
    }
    fn plugin(name: &str) -> Recipient {
        let hrp = bech32::Hrp::parse(&format!("age1{name}")).unwrap();
        Recipient::parse(&bech32::encode::<bech32::Bech32>(hrp, &[3u8; 32]).unwrap()).unwrap()
    }

    #[test]
    fn rules() {
        assert_eq!(
            check_recipients(&[], false, false),
            Err(PolicyError::NoRecipients)
        );
        assert_eq!(
            check_recipients(&[x()], true, false),
            Err(PolicyError::PassphraseMustBeAlone)
        );
        assert_eq!(check_recipients(&[], true, false), Ok(()));
        assert_eq!(check_recipients(&[x()], false, false), Ok(()));
        assert_eq!(
            check_recipients(&[plugin("yubikey")], false, false),
            Err(PolicyError::HardwareOnlyNeedsRecovery)
        );
        assert_eq!(check_recipients(&[plugin("yubikey")], false, true), Ok(()));
        assert_eq!(
            check_recipients(&[plugin("yubikey"), x()], false, false),
            Ok(())
        );
        assert_eq!(
            check_recipients(&[plugin("evil")], false, true),
            Err(PolicyError::PluginNotAllowed("evil".into()))
        );
        assert!(plugin_allowed("tpm") && !plugin_allowed("foo"));
    }
}
