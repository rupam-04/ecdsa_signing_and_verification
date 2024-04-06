use std::{env, str::FromStr};
use ecdsa_signing::app::WorkingMode;
use ecdsa_signing::crypto::{ethereum, secp256k1};
use ecdsa_signing::file_manipulation;
use std::fs::File;
use std::io::Write;


fn main() {
    let args: Vec<String> = env::args().collect();
    let mode: WorkingMode = WorkingMode::from_str(args[1].as_str()).expect("Working mode");

    match mode {
        WorkingMode::KeyPairGeneration => {
            let raw_pr_key = args[2].clone().to_lowercase();

            assert!(raw_pr_key.len() == 64, "Private key must be 64 characters long");
            assert!(raw_pr_key.chars().into_iter().all(|c| u8::from_str_radix(c.to_string().as_str(), 16).unwrap() < 16), "Private key must be a hex string");

            let pub_key = secp256k1::get_public_key(&raw_pr_key);
            let address = ethereum::derive_address(&pub_key);

            let mut private_key_output = File::create(format!("./ECDSA_PrivateKey_{}", address)).expect("create file");
            let mut public_key_output = File::create(format!("./ECDSA_PublicKey_{}", address)).expect("create file");

            write!(&mut private_key_output,
                "[ECDSA Private Key File]\n\nNetwork: {}\nAddress: {}\nPrivate Key[*]: {}\n\n[*] Do not share this key with anyone!",
                "Ethereum",
                address,
                raw_pr_key
            ).expect("write to file");

            write!(&mut public_key_output,
                "[ECDSA Public Key File]\n\nNetwork: {}\nAddress: {}\nUncompressed Public Key: {}\n",
                "Ethereum",
                address,
                pub_key
            ).expect("write to file");
        },
        WorkingMode::Sign => {
            let target_file_path = args[2].clone();
            let private_key_file = File::open(args[3].clone()).expect("open-private-key-file");

            let h = file_manipulation::calculate_file_hash(&target_file_path).expect("file-hash");
            let pr_key = file_manipulation::get_private_key(&private_key_file).expect("private-key");

            let sig = secp256k1::sign_ecdsa(&h, &pr_key);

            let mut signature_output = File::create(format!("./ECDSA_Signature")).expect("create file");

            write!(&mut signature_output,
                "{}",
                sig
            ).expect("write to file");
        },
        WorkingMode::Verify => {
            let target_file_path = args[2].clone();
            let public_key_file = File::open(args[3].clone()).expect("open-public-key-file");

            let (pub_address, pub_key) = file_manipulation::get_public_key(&public_key_file).expect("public-key");
            let h = file_manipulation::calculate_file_hash(&target_file_path).expect("file-hash");

            let signature_file = File::open(args[4].clone()).expect("open-signature-file");
            let signature = file_manipulation::get_signature(&signature_file).expect("signature");

            let r1 = secp256k1::verify_signature(&h, &signature, &pub_key);

            let address = ethereum::derive_address(&pub_key);
            let r2 = pub_address == address;

            if r1 && r2 {
                println!("Signature is valid and the public key is correct");
            }
            else {
                panic!("Signature is invalid or the public key is incorrect");
            }
        }
    }
}

