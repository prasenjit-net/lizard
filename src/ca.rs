//! The CA's root keypair/certificate and leaf-signing primitive.

use std::fs;

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SerialNumber,
};
use rustls_pki_types::CertificateSigningRequestDer;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::config::CaConfig;
use crate::error::{AppError, AppResult};

/// A freshly issued leaf certificate: its PEM encoding (for storage/
/// download), the serial number rcgen assigned it (so callers can record
/// the *actual* embedded serial rather than inventing their own id for
/// the same certificate), and the raw DER (so callers can hash it —
/// revocation matches a client-submitted certificate back to a stored
/// row by DER hash rather than parsing ASN.1 out of untrusted input).
pub struct IssuedCertificate {
    pub pem: String,
    pub serial: String,
    pub der: Vec<u8>,
    /// RFC 3339, matching the validity window actually embedded in the
    /// certificate (the exact `now`/`now + validity_days` this method
    /// signed with) rather than a value the caller would otherwise have
    /// to recompute and hope stays in sync.
    pub not_before: String,
    pub not_after: String,
}

/// Owns the CA's root keypair + certificate and signs leaf certificates
/// from client-submitted CSRs.
pub struct Ca {
    root_cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

impl Ca {
    /// Loads the root CA from the paths in `config`, generating a fresh
    /// self-signed root and writing it to those paths if they don't exist
    /// yet.
    pub fn load_or_generate(config: &CaConfig) -> AppResult<Ca> {
        let root_exists = config.root_cert_path.exists() && config.root_key_path.exists();
        let (cert_pem, key_pem) = if root_exists {
            (
                fs::read_to_string(&config.root_cert_path)?,
                fs::read_to_string(&config.root_key_path)?,
            )
        } else {
            let (cert_pem, key_pem) = generate_root(config.root_validity_years)?;
            write_root(config, &cert_pem, &key_pem)?;
            tracing::warn!(
                cert = %config.root_cert_path.display(),
                "generated a new CA root; install it in the trust stores of anything that \
                 should accept certificates this server issues",
            );
            (cert_pem, key_pem)
        };

        let key_pair = KeyPair::from_pem(&key_pem)?;
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair)?;
        Ok(Ca {
            root_cert_pem: cert_pem,
            issuer,
        })
    }

    /// The root CA certificate in PEM format, for installing into trust
    /// stores or serving to operators.
    pub fn root_cert_pem(&self) -> &str {
        &self.root_cert_pem
    }

    /// Signs a DER-encoded CSR into a leaf certificate chained to this CA's
    /// root, valid for `validity_days` starting now.
    ///
    /// The CSR's own requested extensions (basic constraints, key usage)
    /// are deliberately ignored: honoring a CSR-supplied `CA:TRUE` would
    /// let a client mint its own subordinate CA. Every leaf certificate
    /// this issues gets the same fixed, non-CA, TLS-server key usage
    /// regardless of what the CSR asked for.
    pub fn sign_csr(&self, csr_der: &[u8], validity_days: i64) -> AppResult<IssuedCertificate> {
        let der = CertificateSigningRequestDer::from(csr_der);
        let mut csr_params = CertificateSigningRequestParams::from_der(&der)?;

        let now = OffsetDateTime::now_utc();
        csr_params.params.not_before = now;
        csr_params.params.not_after = now + Duration::days(validity_days);
        let serial = random_serial();
        csr_params.params.serial_number = Some(serial.clone());
        csr_params.params.is_ca = IsCa::ExplicitNoCa;
        csr_params.params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        csr_params.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        csr_params.params.use_authority_key_identifier_extension = true;

        let not_before = now
            .format(&Rfc3339)
            .map_err(|err| AppError::Internal(format!("failed to format not_before: {err}")))?;
        let not_after = csr_params
            .params
            .not_after
            .format(&Rfc3339)
            .map_err(|err| AppError::Internal(format!("failed to format not_after: {err}")))?;

        let cert = csr_params.signed_by(&self.issuer)?;
        Ok(IssuedCertificate {
            pem: cert.pem(),
            serial: serial.to_string(),
            der: cert.der().to_vec(),
            not_before,
            not_after,
        })
    }
}

fn generate_root(validity_years: i64) -> AppResult<(String, String)> {
    let key_pair = KeyPair::generate()?;

    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "Lizard Root CA");

    // CertificateParams is #[non_exhaustive], so it can't be built with
    // struct-literal `..Default::default()` syntax outside rcgen — start
    // from the default and mutate the fields we care about instead.
    let now = OffsetDateTime::now_utc();
    let mut params = CertificateParams::default();
    params.not_before = now;
    params.not_after = now + Duration::days(validity_years * 365);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.distinguished_name = distinguished_name;

    let cert = params.self_signed(&key_pair)?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}

/// A random RFC 5280 serial number (20 bytes, MSB cleared so it encodes as
/// a non-negative integer). rcgen derives a serial from the public key when
/// none is set, which would collide if a client ever reused a key across
/// orders — every issued cert needs its own row in the `certificates`
/// table, so the serial must be unique regardless of the requesting key.
fn random_serial() -> SerialNumber {
    use rand::RngCore;
    let mut bytes = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes[0] &= 0x7f;
    SerialNumber::from_slice(&bytes)
}

fn write_root(config: &CaConfig, cert_pem: &str, key_pem: &str) -> AppResult<()> {
    if let Some(parent) = config.root_cert_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = config.root_key_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&config.root_cert_path, cert_pem)?;
    fs::write(&config.root_key_path, key_pem)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&config.root_key_path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn test_config(dir: &TempDir) -> CaConfig {
        CaConfig {
            root_cert_path: dir.path().join("root-cert.pem"),
            root_key_path: dir.path().join("root-key.pem"),
            root_validity_years: 10,
            cert_validity_days: 90,
            db_path: dir.path().join("lizard.db"),
        }
    }

    fn leaf_csr_der(domain: &str) -> Vec<u8> {
        let key_pair = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec![domain.to_string()]).unwrap();
        params.serialize_request(&key_pair).unwrap().der().to_vec()
    }

    #[test]
    fn generates_a_root_on_first_run_and_writes_it_to_disk() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);

        let ca = Ca::load_or_generate(&config).unwrap();

        assert!(config.root_cert_path.exists());
        assert!(config.root_key_path.exists());
        assert!(ca.root_cert_pem().contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn reloads_the_same_root_on_second_run() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);

        let first = Ca::load_or_generate(&config).unwrap();
        let second = Ca::load_or_generate(&config).unwrap();

        assert_eq!(first.root_cert_pem(), second.root_cert_pem());
    }

    #[test]
    fn signs_a_csr_into_a_cert_chaining_to_the_root() {
        let dir = TempDir::new().unwrap();
        let ca = Ca::load_or_generate(&test_config(&dir)).unwrap();

        let csr_der = leaf_csr_der("service.internal.example");
        let issued = ca.sign_csr(&csr_der, 90).unwrap();
        let leaf_pem = issued.pem;

        assert!(leaf_pem.contains("BEGIN CERTIFICATE"));
        assert!(!issued.serial.is_empty());
        assert!(!issued.der.is_empty());
        assert!(issued.not_before < issued.not_after);

        // Re-parse the root and leaf and confirm the leaf's issuer really
        // is this CA — a wrong-key or wrong-params bug would otherwise
        // still produce a well-formed, but non-chaining, certificate.
        let root_der = pem::parse(ca.root_cert_pem()).unwrap().into_contents();
        let leaf_der = pem::parse(&leaf_pem).unwrap().into_contents();
        let (_, root) = x509_parser::parse_x509_certificate(&root_der).unwrap();
        let (_, leaf) = x509_parser::parse_x509_certificate(&leaf_der).unwrap();
        assert_eq!(leaf.issuer(), root.subject());
        leaf.verify_signature(Some(root.public_key())).unwrap();
    }

    #[test]
    fn ignores_a_csr_requesting_ca_true() {
        let dir = TempDir::new().unwrap();
        let ca = Ca::load_or_generate(&test_config(&dir)).unwrap();

        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["evil.example".to_string()]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let csr_der = params.serialize_request(&key_pair).unwrap().der().to_vec();

        let leaf_pem = ca.sign_csr(&csr_der, 90).unwrap().pem;

        let leaf_der = pem::parse(&leaf_pem).unwrap().into_contents();
        let (_, leaf) = x509_parser::parse_x509_certificate(&leaf_der).unwrap();
        assert!(!leaf.basic_constraints().unwrap().unwrap().value.ca);
    }
}
