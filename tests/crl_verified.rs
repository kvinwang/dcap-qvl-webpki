#![cfg(all(feature = "alloc", any(feature = "ring", feature = "rustcrypto")))]

use core::time::Duration;

use pki_types::{CertificateDer, UnixTime};
use webpki::{
    CertRevocationList, Error, KeyUsage, OwnedCertRevocationList, RevocationCheckDepth,
    RevocationOptionsBuilder, UnknownStatusPolicy, anchor_from_trusted_cert,
};

const EE: &[u8] = include_bytes!("client_auth_revocation/no_ku_chain.ee.der");
const INT_A: &[u8] = include_bytes!("client_auth_revocation/no_ku_chain.int.a.ca.der");
const INT_B: &[u8] = include_bytes!("client_auth_revocation/no_ku_chain.int.b.ca.der");
const ROOT: &[u8] = include_bytes!("client_auth_revocation/no_ku_chain.root.ca.der");

fn spki(cert: &[u8]) -> Vec<u8> {
    let cert = CertificateDer::from(cert);
    anchor_from_trusted_cert(&cert)
        .unwrap()
        .subject_public_key_info
        .to_vec()
}

fn verified(crl: &[u8], issuer: &[u8]) -> Result<OwnedCertRevocationList, Error> {
    OwnedCertRevocationList::from_der_verified(crl, &spki(issuer), webpki::ALL_VERIFICATION_ALGS)
}

fn check_ee(crl: OwnedCertRevocationList) -> Result<(), Error> {
    let crl = CertRevocationList::from(crl);
    let crls = &[&crl];
    let revocation = RevocationOptionsBuilder::new(crls)
        .unwrap()
        .with_depth(RevocationCheckDepth::EndEntity)
        .with_status_policy(UnknownStatusPolicy::Deny)
        .build();
    let root = CertificateDer::from(ROOT);
    let ee = CertificateDer::from(EE);
    webpki::EndEntityCert::try_from(&ee)
        .unwrap()
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &[anchor_from_trusted_cert(&root).unwrap()],
            &[CertificateDer::from(INT_A), CertificateDer::from(INT_B)],
            UnixTime::since_unix_epoch(Duration::from_secs(0x1fed_f00d)),
            KeyUsage::client_auth(),
            Some(revocation),
            None,
        )
        .map(|_| ())
}

#[test]
fn verified_crl_not_revoked() {
    let crl = include_bytes!("client_auth_revocation/ee_not_revoked_ee_depth.crl.der");
    assert_eq!(check_ee(verified(crl, INT_A).unwrap()), Ok(()));
}

#[test]
fn verified_crl_still_reports_revocation() {
    let crl = include_bytes!("client_auth_revocation/ee_revoked_no_ku_ee_depth.crl.der");
    assert_eq!(
        check_ee(verified(crl, INT_A).unwrap()),
        Err(Error::CertRevoked)
    );
}

#[test]
fn verified_crl_rejects_wrong_issuer() {
    let crl = include_bytes!("client_auth_revocation/ee_not_revoked_ee_depth.crl.der");
    assert_eq!(
        verified(crl, ROOT).unwrap_err(),
        Error::InvalidCrlSignatureForPublicKey
    );
}

#[test]
fn verified_crl_rejects_bad_signature() {
    let crl = include_bytes!("client_auth_revocation/ee_revoked_badsig_ee_depth.crl.der");
    assert_eq!(
        verified(crl, INT_A).unwrap_err(),
        Error::InvalidCrlSignatureForPublicKey
    );
}
