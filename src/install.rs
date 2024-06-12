use std::fs;
use std::process::Command;
use std::env;

pub fn install_cert_on_windows(cert_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // 检查证书是否已安装
    let output = Command::new("certutil")
        .args(&["-verifystore", "Root", cert_path])
        .output()?;
    if output.status.success() {
        println!("Certificate is already installed.");
        return Ok(());
    }

    // 安装证书
    let output = Command::new("certutil")
        .args(&["-addstore", "Root", cert_path])
        .output()?;
    if !output.status.success() {
        return Err(format!("Failed to install certificate: {:?}", output).into());
    }
    Ok(())
}

pub fn install_cert_on_macos(cert_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // 检查证书是否已安装
    let output = Command::new("security")
        .args(&["find-certificate", "-a", "-c", "proxylea_cert", "/Library/Keychains/System.keychain"])
        .output()?;
    if output.status.success() {
        println!("Certificate is already installed.");
        return Ok(());
    }

    // 安装证书
    let output = Command::new("sudo")
        .args(&["security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", cert_path])
        .output()?;
    if !output.status.success() {
        return Err(format!("Failed to install certificate: {:?}", output).into());
    }
    Ok(())
}

pub fn install_cert_on_linux(cert_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // 检查证书是否已安装
    let cert_name = format!("/usr/local/share/ca-certificates/{}", cert_path);
    if fs::metadata(&cert_name).is_ok() {
        println!("Certificate is already installed.");
        return Ok(());
    }

    // 安装证书
    let output = Command::new("sudo")
        .args(&["cp", cert_path, "/usr/local/share/ca-certificates/"])
        .output()?;
    if !output.status.success() {
        return Err(format!("Failed to copy certificate: {:?}", output).into());
    }

    let output = Command::new("sudo")
        .arg("update-ca-certificates")
        .output()?;
    if !output.status.success() {
        return Err(format!("Failed to update CA certificates: {:?}", output).into());
    }
    Ok(())
}

pub fn install_cert() -> Result<(), Box<dyn std::error::Error>> {
    // 假设证书路径为当前目录下的 "proxylea_cert.crt"
    let cert_path = "src/proxylea_cert.crt";
    
    // 根据操作系统选择安装方法
    if cfg!(target_os = "windows") {
        install_cert_on_windows(cert_path)?;
    } else if cfg!(target_os = "macos") {
        install_cert_on_macos(cert_path)?;
    } else if cfg!(target_os = "linux") {
        install_cert_on_linux(cert_path)?;
    } else {
        return Err("Unsupported operating system".into());
    }

    println!("Certificate installed successfully.");
    Ok(())
}
