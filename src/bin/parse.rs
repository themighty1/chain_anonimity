use anyhow::{Error, Result};
use lazy_static::lazy_static;
use std::{
    collections::HashMap,
    fs::{self},
    path::Path,
};
use webpki_root_certs::TLS_SERVER_ROOT_CERTS;
use x509_parser::parse_x509_certificate;

lazy_static! {
    static ref OID_TO_NAME: HashMap<&'static str, &'static str> = {
        let mut oid_to_name = HashMap::new();
        oid_to_name.insert("1.2.840.113549.1.1.1", "rsaEncryption");
        oid_to_name.insert("1.2.840.113549.1.1.5", "sha1WithRSAEncryption");
        oid_to_name.insert("1.2.840.113549.1.1.11", "sha256WithRSAEncryption");
        oid_to_name.insert("1.2.840.113549.1.1.12", "sha384WithRSAEncryption");
        oid_to_name.insert("1.2.840.113549.1.1.13", "sha512WithRSAEncryption");
        oid_to_name.insert("1.2.840.10045.4.3.2", "ecdsaWithSHA256");
        oid_to_name.insert("1.2.840.10045.4.3.3", "ecdsaWithSHA384");
        oid_to_name.insert("1.3.132.0.34", "secp384r1");
        oid_to_name.insert("1.2.840.10045.3.1.7", "secp256r1");
        oid_to_name.insert("1.2.840.10045.2.1", "ecPublicKey");
        oid_to_name
    };
    static ref OID_TO_TYPE: HashMap<&'static str, &'static str> = {
        let mut oid_to_type = HashMap::new();
        oid_to_type.insert("1.2.840.113549.1.1.1", "RSA");
        oid_to_type.insert("1.2.840.113549.1.1.5", "RSA");
        oid_to_type.insert("1.2.840.113549.1.1.11", "RSA");
        oid_to_type.insert("1.2.840.113549.1.1.12", "RSA");
        oid_to_type.insert("1.2.840.113549.1.1.13", "RSA");
        oid_to_type.insert("1.2.840.10045.4.3.2", "ECDSA");
        oid_to_type.insert("1.2.840.10045.4.3.3", "ECDSA");
        oid_to_type.insert("1.2.840.10045.2.1", "ECDSA");
        oid_to_type
    };
    static ref OID_TO_HASH: HashMap<&'static str, &'static str> = {
        let mut oid_to_hash = HashMap::new();
        oid_to_hash.insert("1.2.840.113549.1.1.5", "SHA1");
        oid_to_hash.insert("1.2.840.113549.1.1.11", "SHA256");
        oid_to_hash.insert("1.2.840.113549.1.1.12", "SHA384");
        oid_to_hash.insert("1.2.840.113549.1.1.13", "SHA512");
        oid_to_hash.insert("1.2.840.10045.4.3.2", "SHA256");
        oid_to_hash.insert("1.2.840.10045.4.3.3", "SHA384");
        oid_to_hash
    };
    static ref OID_TO_PARAM: HashMap<&'static str, &'static str> = {
        let mut oid_to_param = HashMap::new();
        oid_to_param.insert("1.3.132.0.34", "P384");
        oid_to_param.insert("1.2.840.10045.3.1.7", "P256");
        oid_to_param
    };

    /// Maps root cert's subject name to its cert.
    static ref ROOT_MAP: HashMap<Vec<u8>, Vec<u8>> = {
        let mut root_map = HashMap::new();
        for root in TLS_SERVER_ROOT_CERTS {
            let (_, cert) = parse_x509_certificate(root).unwrap();
            root_map.insert(cert.subject().as_raw().to_vec(), root.to_vec());
        }
        root_map
    };
}

type X509 = Vec<u8>;
type X509chain = Vec<X509>;

#[derive(Eq, Hash, PartialEq, Clone)]
struct Algorithm {
    // Type: ECDSA or RSA.
    typ: String,
    // For ECDSA: P256, P384. For RSA: 2048, 3072, 4096.
    param: String,
    // Either SHA1, SHA256, SHA384, SHA512.
    hash: String,
}

/// A fingerprint contains attributes related to an x509 chain which will be made public
/// during zk cert verification.
#[derive(Eq, Hash, PartialEq, Clone, Default)]
struct Fingerprint {
    /// The length of the chain including the root CA cert.
    chain_len: usize,
    /// Issuer signature algorithm, starting from the issuer of the end-entity cert,
    /// not including the issuer of the CA cert.
    signatures: Vec<Algorithm>,
}

fn main() -> Result<()> {
    let chains = read_chains()?;
    let mut fingerprints = Vec::new();

    for chain in chains {
        match process_chain(chain).unwrap() {
            Some(fingerprint) => {
                fingerprints.push(fingerprint);
            }
            None => continue,
        }
    }

    // Split fingerprints into pools, keeping track of the pool size.
    let mut pools: HashMap<Fingerprint, usize> = HashMap::new();
    for f in fingerprints.iter() {
        let old_size = match pools.get(f) {
            Some(size) => *size,
            None => 0,
        };
        pools.insert(f.clone(), old_size + 1);
    }

    // Sort by size descendingly.
    let mut pools: Vec<(Fingerprint, usize)> = pools.clone().into_iter().collect();
    pools.sort_by(|a, b| b.1.cmp(&a.1));

    println!(
        "Total {:?} fingerprints in {:?} pools",
        fingerprints.len(),
        pools.len()
    );
    println!("Pool size  % of total         Pool fingerprint (chain_length|sig|sig|...)");
    println!();

    let total = fingerprints.len();
    let mut sum = 0;

    for p in pools {
        let fp = p.0;

        let mut fpstr = String::new();
        fpstr.push_str(&fp.chain_len.to_string());

        for sig in fp.signatures {
            fpstr.push_str(&format!("|{}-{}-{}", sig.typ, sig.param, sig.hash));
        }

        sum += p.1;
        println!(
            "{:<width1$} {:<width1$} {:<width1$}",
            p.1,
            ((sum as f32 / total as f32) * 100_f32) as usize,
            fpstr,
            width1 = 10
        );
    }

    Ok(())
}

fn read_chains() -> Result<Vec<X509chain>> {
    let path = Path::new("chains");

    if !path.exists() {
        return Err(Error::msg("chains folder does not exist"));
    }

    // Cert chain for each of the ~1000 domains.
    let mut chains = Vec::with_capacity(1000);

    for entry in fs::read_dir(path)? {
        let dir_path = entry?.path();
        let mut chain: X509chain = Vec::with_capacity(4);
        // The dir contains files 0, 1, 2 etc for each cert in the chain.
        for i in 0..6 {
            let cert_path = dir_path.join(i.to_string());
            if !cert_path.exists() {
                break;
            }
            if i == 5 {
                return Err(Error::msg("expecting at most 5 certs in the chain"));
            }
            let x509 = fs::read(dir_path.join(i.to_string()))?;
            chain.push(x509);
        }
        assert!(chain.len() >= 2);
        chains.push(chain);
    }

    Ok(chains)
}

// Collects a fingerprint for the chain.
fn process_chain(mut chain: X509chain) -> Result<Option<Fingerprint>> {
    // Some websites don't send a root CA cert. We need to know if that's the case.
    let last = chain.last().unwrap();
    let (_, last_cert) = parse_x509_certificate(last)?;
    // Root CA certs are always self-issued.
    if last_cert.issuer() != last_cert.subject() {
        // Append the root CA.
        let root_cert = ROOT_MAP.get(&last_cert.issuer().as_raw().to_vec());
        if let Some(root_cert) = root_cert {
            chain.push(root_cert.clone());
        } else {
            // Root cert not found in store.
            return Ok(None);
        };
    }

    // Collect sigs from all certs except the root CA cert.
    let mut signatures = Vec::new();

    for certs in chain.windows(2) {
        let (subject, issuer) = (certs.first().unwrap(), certs.last().unwrap());

        let (_, subj_cert) = parse_x509_certificate(subject).unwrap();
        let subj_alg = subj_cert.signature_algorithm.oid().to_string();
        let sig_type = OID_TO_TYPE.get(subj_alg.as_str()).unwrap().to_string();

        // Pubkey info can only be derived from the issuer's cert.
        let (_, issuer_cert) = parse_x509_certificate(issuer).unwrap();
        let issuer_pk = issuer_cert.public_key();

        // Sanity-check: sig type must match pk type.
        assert_eq!(
            sig_type,
            OID_TO_TYPE
                .get(issuer_pk.algorithm.oid().to_id_string().as_str())
                .unwrap()
                .to_string()
        );

        let param = if sig_type == "RSA" {
            // RSA key size cannot be inferred from OIDs, only by calculating it directly.
            match issuer_pk.parsed().unwrap().key_size() {
                2048 => "2048".to_string(),
                3072 => "3072".to_string(),
                4096 => "4096".to_string(),
                _ => unimplemented!(),
            }
        } else {
            // For ECDSA the info about the curve is an pk params.
            let id = issuer_pk
                .algorithm
                .parameters()
                .unwrap()
                .clone()
                .oid()
                .unwrap()
                .to_id_string();
            OID_TO_PARAM.get(id.as_str()).unwrap().to_string()
        };

        signatures.push(Algorithm {
            typ: sig_type,
            param,
            hash: OID_TO_HASH.get(subj_alg.as_str()).unwrap().to_string(),
        });
    }

    Ok(Some(Fingerprint {
        chain_len: chain.len(),
        signatures,
    }))
}
