use std::{fs::File, io::Read, path::Path};
use openssl::asn1::Asn1Integer;
use openssl::bn::BigNum;
use openssl::rand;
use openssl::pkey::{Private, PKey};
use openssl::rsa::Rsa;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::X509;

// 函数：加载根证书和私钥
fn load_root_cert_and_key(
    root_cert_path: &str,
    root_key_path: &str,
) -> Result<(X509, PKey<Private>), Box<dyn std::error::Error>> {
    // 检查根证书文件是否存在
    if !Path::new(root_cert_path).exists() {
        return Err(format!("根证书文件未找到: {}", root_cert_path).into());
    }

    // 加载根证书
    let mut ca_file = File::open(root_cert_path)?;
    let mut ca_bytes = Vec::new();
    ca_file.read_to_end(&mut ca_bytes)?;
    let ca = X509::from_pem(&ca_bytes)?;

    // 检查根密钥文件是否存在
    if !Path::new(root_key_path).exists() {
        return Err(format!("根密钥文件未找到: {}", root_key_path).into());
    }

    // 加载根密钥
    let mut pkey_file = File::open(root_key_path)?;
    let mut pkey_bytes = Vec::new();
    pkey_file.read_to_end(&mut pkey_bytes)?;
    let pkey = PKey::private_key_from_pem(&pkey_bytes)?;

    Ok((ca, pkey))
}

// 函数：客户端动态颁发证书
fn client_cert_signing(
    root_cert_path: &str,
    root_key_path: &str,
    host: &str,
) -> Result<(X509, PKey<Private>), Box<dyn std::error::Error>> {
    // 加载根证书和私钥
    let (root_cert, root_key) = load_root_cert_and_key(root_cert_path, root_key_path)?;

    // 生成密钥对
    let rsa = Rsa::generate(2048)?;
    let private_key = PKey::from_rsa(rsa)?;

    let public_key_pem = private_key.public_key_to_pem()?;
    let public_key = PKey::public_key_from_pem(&public_key_pem)?;

    // 颁发证书
    let mut cert = X509::builder()?;
    cert.set_version(2)?;

    let mut x509_name = openssl::x509::X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "ZH")?;
    x509_name.append_entry_by_text("ST", "SC")?;
    x509_name.append_entry_by_text("L", "YC")?;
    x509_name.append_entry_by_text("O", "YC")?;
    x509_name.append_entry_by_text("OU", "YC")?;
    x509_name.append_entry_by_text("CN", host)?;
    let x509_name = x509_name.build();

    cert.set_subject_name(&x509_name)?;
    cert.set_issuer_name(&root_cert.subject_name())?;

    let mut serial_number = [0; 16];
    rand::rand_bytes(&mut serial_number)?;
    let serial_number = BigNum::from_slice(&serial_number)?;
    let serial_number = Asn1Integer::from_bn(&serial_number)?;
    cert.set_serial_number(&serial_number)?;

    cert.set_not_before(root_cert.not_before())?;
    cert.set_not_after(root_cert.not_after())?;
    cert.set_pubkey(&public_key)?;

    let alternative_name = SubjectAlternativeName::new()
        .dns(host)
        .build(&cert.x509v3_context(Some(&root_cert), None))?;
    cert.append_extension(alternative_name)?;

    cert.sign(&root_key, openssl::hash::MessageDigest::sha256())?;

    Ok((cert.build(), private_key))
}

// 公共函数：获取证书和密钥
pub fn get_crt_key(host: &str) -> Result<(X509, PKey<Private>), Box<dyn std::error::Error>> {
    println!("主机: {:?}", host);
    client_cert_signing("src/proxylea_cert.crt", "src/proxylea_private.key", host)
}

// 主函数：示例用法
// fn main() {
//     let host = "example.com";
//     match get_crt_key(host) {
//         Ok((cert, key)) => {
//             println!("证书和密钥已成功生成，主机: {}", host);
//         }
//         Err(e) => {
//             eprintln!("生成证书和密钥时出错: {:?}", e);
//         }
//     }
// }
