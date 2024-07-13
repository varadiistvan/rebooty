use aes_gcm::{
    aead::{generic_array::GenericArray, Aead},
    Aes256Gcm, KeyInit,
};
use chrono::{DateTime, Duration, Utc};
use nix::{ifaddrs, sys::reboot};
use openssl::{
    pkey::{PKey, Public},
    rsa::{Padding, Rsa},
    sign::Verifier,
};
use russh_keys::{key::PublicKey, parse_public_key_base64};
use std::{collections::HashMap, io::BufReader, net::IpAddr};

fn read_authorized_keys() -> Vec<PKey<Public>> {
    let file = std::fs::File::open(format!(
        "{}/.ssh/authorized_keys",
        std::env::var("HOME").unwrap()
    ))
    .unwrap();
    let authorized_keys = std::io::read_to_string(BufReader::new(file)).unwrap();

    let mut pub_keys = Vec::new();

    for line in authorized_keys.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let key_data = parts[1];
            if let Ok(PublicKey::RSA { key, hash: _ }) = parse_public_key_base64(key_data) {
                let pub_key_der = key.0.public_key_to_der().unwrap();
                let rsa_pub = Rsa::public_key_from_der(&pub_key_der).unwrap();
                let pub_key = PKey::from_rsa(rsa_pub).unwrap();
                pub_keys.push(pub_key);
            }
        }
    }

    pub_keys
}

fn verify_signature(message: &[u8], signature: &[u8], keys: &[PKey<Public>]) -> bool {
    println!("Keys: {:?}", keys);
    for pub_key in keys {
        let mut verifier = Verifier::new(openssl::hash::MessageDigest::sha256(), pub_key).unwrap();
        verifier.update(message).unwrap();
        if verifier.verify(signature).unwrap() {
            return true;
        }
    }
    false
}

fn verify_mac_address(data: &[u8], expected_mac: &[u8]) -> bool {
    if data.len() != expected_mac.len() {
        return false;
    }
    data.iter().zip(expected_mac.iter()).all(|(a, b)| a == b)
}

fn reboot_system() {
    // Using nix crate to reboot the system
    unsafe { nix::libc::sync() };
    reboot::reboot(reboot::RebootMode::RB_AUTOBOOT).expect("Failed to reboot the system");
    std::process::exit(0)
}

fn get_mac() -> [u8; 6] {
    let ifiter = ifaddrs::getifaddrs().unwrap();
    for interface in ifiter {
        if let Some(iface_address) = interface.address {
            if let Some(link) = iface_address.as_link_addr() {
                let bytes = link.addr();

                if let Some(bytes) = bytes {
                    if !bytes.iter().any(|byte| byte == &0) {
                        return bytes;
                    }
                }
            }
        }
    }
    panic!("No MAC address found!")
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let port = std::env::var("PORT").unwrap_or("52424".to_owned());
    let socket = tokio::net::UdpSocket::bind(format!("0.0.0.0:{port}"))
        .await
        .unwrap();
    println!("Listening on port {}", port);
    let expected_mac = get_mac();
    println!(
        "{:?}",
        expected_mac
            .iter()
            .fold(String::new(), |acc, byte| format!("{acc}:{:02x}", byte))
    );

    let keys = read_authorized_keys();

    let mut clients: HashMap<IpAddr, (DateTime<Utc>, i64)> = HashMap::new();

    loop {
        let mut buf = [0; 1024];
        if let Ok((amt, src)) = socket.recv_from(&mut buf).await {
            if let Some(when) = clients.get(&src.ip()) {
                if when.0 > Utc::now() {
                    continue;
                }
            }

            clients
                .entry(src.ip())
                .and_modify(|existing| {
                    existing.0 = Utc::now() + Duration::seconds(existing.1);
                    println!("IP {} is out for {} seconds", src.ip(), existing.1);
                    existing.1 = existing.1.saturating_mul(2);
                    if existing.1 > i64::MAX / 1_000 {
                        existing.1 = i64::MAX / 1_000
                    }
                })
                .or_insert((Utc::now() + Duration::seconds(20), 20));

            let received_data = &buf[..amt];

            if received_data.len() < 384 {
                continue;
            }
            for key in &keys {
                let mut decrypted_nonce_and_key = vec![0; key.size()];

                match key.rsa().unwrap().public_decrypt(
                    &received_data[received_data.len() - 384..],
                    &mut decrypted_nonce_and_key,
                    Padding::PKCS1,
                ) {
                    Ok(_) => {
                        let nonce = &decrypted_nonce_and_key[0..12];
                        let key = &decrypted_nonce_and_key[12..44];

                        let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
                        let nonce = GenericArray::from_slice(nonce);

                        let received_data = cipher
                            .decrypt(nonce, &received_data[0..received_data.len() - 384])
                            .unwrap();

                        let mac_part = &received_data[0..6];
                        let signature_part = &received_data[6..];

                        if verify_signature(mac_part, signature_part, &keys)
                            && verify_mac_address(mac_part, &expected_mac)
                        {
                            println!("Correct MAC address received. Rebooting system...");
                            reboot_system()
                        }
                    }
                    Err(e) => {
                        dbg!(e);
                    }
                }
            }
        }
    }
}
