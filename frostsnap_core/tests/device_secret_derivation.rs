use frostsnap_core::device::{DevicePrf, DeviceSecretDerivation};
use frostsnap_core::nonce_stream::NonceStreamId;
use frostsnap_core::{AccessStructureId, AccessStructureRef, KeyId};
use schnorr_fun::fun::s;
use sha2::{Digest, Sha256};

struct Sha256Prf;

impl DevicePrf for Sha256Prf {
    fn prf(&mut self, message: &[&[u8]]) -> [u8; 32] {
        let mut hash = Sha256::new();
        for part in message {
            hash.update(part);
        }
        hash.finalize().into()
    }
}

/// Frozen: these bytes decide every existing device's keys and nonces, its DeviceId included. They
/// were produced by the device's derivations before they moved into frostsnap_core.
#[test]
fn derivation_layouts_are_frozen() {
    let key = Sha256Prf.get_share_encryption_key(
        AccessStructureRef {
            key_id: KeyId([1; 32]),
            access_structure_id: AccessStructureId([2; 32]),
        },
        s!(3).public(),
        "0404040404040404040404040404040404040404040404040404040404040404"
            .parse()
            .unwrap(),
    );
    assert_eq!(
        schnorr_fun::fun::hex::encode(&key.0),
        "672c8455d3a7f8d616032c3b4b47f5d822a0568ab6d5acd7f68ae4bde9a9f91c"
    );

    let seed = Sha256Prf.derive_nonce_seed(NonceStreamId([5; 16]), 0x0102_0304, &[6; 32]);
    assert_eq!(
        schnorr_fun::fun::hex::encode(&seed),
        "79e4faf9eb4b81066e5cc18a159165002c3cd9e340b5f412118ca58b3e992cc1"
    );

    let keypair_secret = Sha256Prf.prf_domain("frostsnap-device-keypair", &[7; 32]);
    assert_eq!(
        schnorr_fun::fun::hex::encode(&keypair_secret),
        "2f9ad85da12250e8566a33269e97db0b82ccd8cbc8d72a4c52878a2b24babfc3"
    );
}
