//! Hybrid (X25519 + ML-KEM-768) wrap of a vault epoch key for enrollment.

use serde::{Deserialize, Serialize};
use shelf_core::{HybridKemPublicKey, ML_KEM_768_PUBLIC_KEY_LEN};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::cipher::{open_xchacha, seal_xchacha};
use crate::error::ProtocolError;

/// Domain for combining hybrid shared secrets.
const DOMAIN_ENROLL_WRAP: &str = "shelf/enrollment/v1";

/// Ciphertext wrapping a 32-byte epoch key to a joining device's hybrid KEM.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridEpochWrap {
    /// Approver ephemeral X25519 public key.
    pub x25519_ephemeral: [u8; 32],
    /// ML-KEM-768 ciphertext.
    pub ml_kem_ciphertext: Vec<u8>,
    /// AEAD nonce.
    pub nonce: [u8; 24],
    /// AEAD ciphertext of the 32-byte epoch key.
    pub ciphertext: Vec<u8>,
}

/// Wrap `epoch_key` to `recipient` (joining device public hybrid KEM).
pub fn wrap_epoch_key(
    epoch_key: &[u8; 32],
    recipient: &HybridKemPublicKey,
) -> Result<HybridEpochWrap, ProtocolError> {
    let eph = StaticSecret::from(rand::random::<[u8; 32]>());
    let eph_pub = PublicKey::from(&eph);
    let their_x = PublicKey::from(*recipient.x25519.as_bytes());
    let x_ss = eph.diffie_hellman(&their_x);

    let (ml_ct, ml_ss) = mlkem_encapsulate(recipient.ml_kem_768.as_bytes())?;
    let wrap_key = combine(&x_ss.to_bytes(), ml_ss.as_slice());
    let nonce: [u8; 24] = rand::random();
    let ciphertext = seal_xchacha(&wrap_key, &nonce, DOMAIN_ENROLL_WRAP.as_bytes(), epoch_key)?;
    Ok(HybridEpochWrap {
        x25519_ephemeral: eph_pub.to_bytes(),
        ml_kem_ciphertext: ml_ct,
        nonce,
        ciphertext,
    })
}

/// Unwrap using the joining device's X25519 static secret and ML-KEM seed.
pub fn unwrap_epoch_key(
    wrap: &HybridEpochWrap,
    x25519_secret: &StaticSecret,
    ml_kem_seed: &[u8],
) -> Result<[u8; 32], ProtocolError> {
    let their_eph = PublicKey::from(wrap.x25519_ephemeral);
    let x_ss = x25519_secret.diffie_hellman(&their_eph);
    let ml_ss = mlkem_decapsulate(ml_kem_seed, &wrap.ml_kem_ciphertext)?;
    let wrap_key = combine(&x_ss.to_bytes(), ml_ss.as_slice());
    let pt = open_xchacha(
        &wrap_key,
        &wrap.nonce,
        DOMAIN_ENROLL_WRAP.as_bytes(),
        &wrap.ciphertext,
    )?;
    pt.as_slice()
        .try_into()
        .map_err(|_| ProtocolError::InvalidDekLength {
            expected: 32,
            actual: pt.len(),
        })
}

fn combine(x: &[u8; 32], ml: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + ml.len());
    buf.extend_from_slice(x);
    buf.extend_from_slice(ml);
    blake3::derive_key(DOMAIN_ENROLL_WRAP, &buf)
}

fn mlkem_encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    use ml_kem::kem::{Encapsulate, Key};
    use ml_kem::{EncapsulationKey, MlKem768};

    if ek_bytes.len() != ML_KEM_768_PUBLIC_KEY_LEN {
        return Err(ProtocolError::WrapFailure);
    }
    let mut key = Key::<EncapsulationKey<MlKem768>>::default();
    key.copy_from_slice(ek_bytes);
    let ek = EncapsulationKey::<MlKem768>::new(&key).map_err(|_| ProtocolError::WrapFailure)?;
    let (ct, ss) = ek.encapsulate();
    Ok((ct.as_slice().to_vec(), ss.as_slice().to_vec()))
}

fn mlkem_decapsulate(seed: &[u8], ct: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    use ml_kem::kem::{Ciphertext, Decapsulate};
    use ml_kem::{DecapsulationKey, MlKem768, Seed};

    if seed.len() != 64 {
        return Err(ProtocolError::WrapFailure);
    }
    let mut seed_arr = Seed::default();
    seed_arr.copy_from_slice(seed);
    let dk = DecapsulationKey::<MlKem768>::from_seed(seed_arr);
    let mut ct_arr = Ciphertext::<MlKem768>::default();
    if ct.len() != ct_arr.len() {
        return Err(ProtocolError::WrapFailure);
    }
    ct_arr.copy_from_slice(ct);
    let ss = dk.decapsulate(&ct_arr);
    Ok(ss.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::kem::KeyExport;
    use ml_kem::{Kem, MlKem768};
    use shelf_core::{MlKem768PublicKey, X25519PublicKey};

    #[test]
    fn hybrid_wrap_round_trip() {
        let (dk, ek) = MlKem768::generate_keypair();
        let x_sec = StaticSecret::from(rand::random::<[u8; 32]>());
        let x_pub = PublicKey::from(&x_sec);
        let recipient = HybridKemPublicKey::new(
            X25519PublicKey::from_bytes(x_pub.to_bytes()),
            MlKem768PublicKey::from_bytes(ek.to_bytes().to_vec()).unwrap(),
        );
        let epoch: [u8; 32] = rand::random();
        let wrap = wrap_epoch_key(&epoch, &recipient).unwrap();
        let opened = unwrap_epoch_key(&wrap, &x_sec, dk.to_bytes().as_slice()).unwrap();
        assert_eq!(opened, epoch);
    }
}
