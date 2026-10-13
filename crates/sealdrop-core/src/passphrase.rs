//! Generated passphrases (spec 5.2). Never accepts user-chosen passwords.

use rand::Rng;
use secrecy::SecretString;
use zeroize::Zeroizing;

pub const EFF_RAW: &str = include_str!("../wordlists/eff_large_wordlist.txt");
pub const BIP39_RAW: &str = include_str!("../wordlists/bip39_english.txt");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordList {
    Eff,
    Bip39,
}

pub struct Passphrase {
    pub words: Zeroizing<Vec<String>>,
    pub entropy_bits: f64,
}

impl Passphrase {
    pub fn joined(&self) -> Zeroizing<String> {
        Zeroizing::new(self.words.join(" "))
    }
    pub fn as_secret(&self) -> SecretString {
        SecretString::from(self.words.join(" "))
    }
}

pub fn min_words(list: WordList) -> usize {
    match list {
        WordList::Eff => 6,
        WordList::Bip39 => 10,
    }
}

pub(crate) fn eff_words() -> Vec<&'static str> {
    EFF_RAW
        .lines()
        .filter_map(|l| l.split('\t').nth(1))
        .map(str::trim)
        .filter(|w| !w.is_empty())
        .collect()
}

pub(crate) fn bip39_words() -> Vec<&'static str> {
    BIP39_RAW
        .lines()
        .map(str::trim)
        .filter(|w| !w.is_empty())
        .collect()
}

/// Generates `max(count, min_words(list))` words from the OS CSPRNG.
pub fn generate(list: WordList, count: usize) -> Passphrase {
    let words = match list {
        WordList::Eff => eff_words(),
        WordList::Bip39 => bip39_words(),
    };
    let n = count.max(min_words(list));
    let mut rng = rand::rng();
    let chosen: Vec<String> = (0..n)
        .map(|_| words[rng.random_range(0..words.len())].to_string())
        .collect();
    let entropy_bits = n as f64 * (words.len() as f64).log2();
    Passphrase {
        words: Zeroizing::new(chosen),
        entropy_bits,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn wordlists_have_expected_sizes_and_checksums() {
        assert_eq!(eff_words().len(), 7776);
        assert_eq!(bip39_words().len(), 2048);
        assert_eq!(
            crate::hashing::sha256_hex(EFF_RAW.as_bytes()),
            "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"
        );
        assert_eq!(
            crate::hashing::sha256_hex(BIP39_RAW.as_bytes()),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
    }

    #[test]
    fn generates_minimum_words_and_entropy() {
        let p = generate(WordList::Eff, 1);
        assert_eq!(p.words.len(), 6);
        assert!((p.entropy_bits - 77.5).abs() < 0.1);
        let p = generate(WordList::Bip39, 10);
        assert_eq!(p.words.len(), 10);
        assert!((p.entropy_bits - 110.0).abs() < 0.1);
        assert_eq!(p.as_secret().expose_secret().split(' ').count(), 10);
    }

    #[test]
    fn two_passphrases_differ() {
        let a = generate(WordList::Eff, 6).joined();
        let b = generate(WordList::Eff, 6).joined();
        assert_ne!(*a, *b);
    }
}
