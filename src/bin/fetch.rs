use anyhow::{anyhow, Result};
use rayon::prelude::*;
use rustls::{
    crypto::{
        aws_lc_rs::{self, cipher_suite, kx_group},
        SupportedKxGroup,
    },
    version, RootCertStore,
};
use serde_json::Value;
use std::{
    fs::{self, File},
    io::Write,
    net::TcpStream,
    path::Path,
    sync::Arc,
};

fn main() -> Result<()> {
    create_folder_if_not_exists("chains")?;

    // Parse the file downloaded from https://dataforseo.com/free-seo-stats/top-1000-websites
    let json = read_json_from_file("ranked_domains.json")?;

    let mut domains = Vec::with_capacity(1000);
    if let Value::Array(array) = json {
        for item in array {
            if let Value::Object(obj) = item {
                if let Value::String(domain) = obj.get("domain").unwrap() {
                    domains.push(domain.clone());
                }
            }
        }
    }

    domains.par_iter_mut().for_each(|domain| {
        let path = Path::new("chains").join(domain.clone());
        // Skip if data is already present from a previous program run.
        if path.exists() {
            return;
        }

        let certs = get_server_certs(domain.clone().as_str()).unwrap();
        println!("Got {:?} certs for domain {:?}", certs.len(), domain);

        fs::create_dir(path.clone()).unwrap();
        for (idx, cert) in certs.iter().enumerate() {
            File::create(path.clone().join(idx.to_string()))
                .unwrap()
                .write_all(cert)
                .unwrap();
        }
    });

    Ok(())
}

fn get_server_certs(domain: &str) -> Result<Vec<Vec<u8>>> {
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    // TLS params supported by TLSNotary.
    let versions = &[&version::TLS12];
    let cipher_suites = &[
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    ];
    let kx_groups: Vec<&'static dyn SupportedKxGroup> = vec![kx_group::SECP256R1];

    let mut crypto_provider = aws_lc_rs::default_provider();
    crypto_provider.cipher_suites = cipher_suites.to_vec();
    crypto_provider.kx_groups = kx_groups;

    let config = rustls::ClientConfig::builder_with_provider(crypto_provider.into())
        .with_protocol_versions(versions)?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = domain.to_string().try_into()?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)?;

    let mut sock = TcpStream::connect((domain, 443))?;
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    tls.flush()?;

    let certs: Vec<_> = tls
        .conn
        .peer_certificates()
        .unwrap()
        .iter()
        .map(|cert| cert.to_vec())
        .collect();

    Ok(certs)
}

fn create_folder_if_not_exists(folder_path: &str) -> Result<()> {
    let path = Path::new(folder_path);

    if !path.exists() {
        fs::create_dir_all(path)?;
    }

    Ok(())
}

fn read_json_from_file(file_path: &str) -> Result<Value> {
    let path = Path::new(file_path);
    let contents = fs::read_to_string(path).map_err(|e| anyhow!("Failed to read file: {}", e))?;

    let json: Value =
        serde_json::from_str(&contents).map_err(|e| anyhow!("Failed to parse JSON: {}", e))?;

    Ok(json)
}
