use std::fs;
use std::process::Command;
use std::error::Error;

pub trait CertManager {
    fn is_cert_installed(&self, cert_path: &str) -> Result<bool, Box<dyn Error>>;
    fn install_cert(&self, cert_path: &str) -> Result<(), Box<dyn Error>>;
    fn delete_cert(&self, cert_path: &str) -> Result<(), Box<dyn Error>>;
}

pub struct WindowsCertManager;

impl CertManager for WindowsCertManager {
    fn is_cert_installed(&self, cert_path: &str) -> Result<bool, Box<dyn Error>> {
        let output = Command::new("certutil")
            .args(&["-verifystore", "Root", cert_path])
            .output()?;
        Ok(output.status.success())
    }

    fn install_cert(&self, cert_path: &str) -> Result<(), Box<dyn Error>> {
        if self.is_cert_installed(cert_path)? {
            println!("Certificate is already installed.");
            return Ok(());
        }

        let output = Command::new("certutil")
            .args(&["-addstore", "Root", cert_path])
            .output()?;
        if !output.status.success() {
            return Err(format!("Failed to install certificate: {:?}", output).into());
        }
        Ok(())
    }

    fn delete_cert(&self, cert_path: &str) -> Result<(), Box<dyn Error>> {
        let output = Command::new("certutil")
            .args(&["-delstore", "Root", cert_path])
            .output()?;
        if !output.status.success() {
            return Err(format!("Failed to delete certificate: {:?}", output).into());
        }
        Ok(())
    }
}

pub struct MacOSCertManager;

impl CertManager for MacOSCertManager {
    fn is_cert_installed(&self, cert_name: &str) -> Result<bool, Box<dyn Error>> {
        let output = Command::new("security")
            .args(&["find-certificate", "-a", "-c", cert_name, "/Library/Keychains/System.keychain"])
            .output()?;
        println!("Certificate installed successfully. {:?}", output.status.success());
        Ok(output.status.success())
    }

    fn install_cert(&self, cert_path: &str) -> Result<(), Box<dyn Error>> {
        if self.is_cert_installed("proxylea_cert")? {
            println!("Certificate is already installed.");
            return Ok(());
        }

        let output = Command::new("sudo")
            .args(&["security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", cert_path])
            .output()?;
        if !output.status.success() {
            return Err(format!("Failed to install certificate: {:?}", output).into());
        }
      
        Ok(())
    }

    fn delete_cert(&self, cert_name: &str) -> Result<(), Box<dyn Error>> {
        let output = Command::new("sudo")
            .args(&["security", "delete-certificate", "-c", cert_name, "/Library/Keychains/System.keychain"])
            .output()?;
        if !output.status.success() {
            return Err(format!("Failed to delete certificate: {:?}", output).into());
        }
        Ok(())
    }
}

pub struct LinuxCertManager;

impl CertManager for LinuxCertManager {
    fn is_cert_installed(&self, cert_path: &str) -> Result<bool, Box<dyn Error>> {
        let cert_name = format!("/usr/local/share/ca-certificates/{}", cert_path);
        Ok(fs::metadata(&cert_name).is_ok())
    }

    fn install_cert(&self, cert_path: &str) -> Result<(), Box<dyn Error>> {
        if self.is_cert_installed(cert_path)? {
            println!("Certificate is already installed.");
            return Ok(());
        }

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

    fn delete_cert(&self, cert_path: &str) -> Result<(), Box<dyn Error>> {
        let cert_name = format!("/usr/local/share/ca-certificates/{}", cert_path);
        let output = Command::new("sudo")
            .args(&["rm", &cert_name])
            .output()?;
        if !output.status.success() {
            return Err(format!("Failed to remove certificate file: {:?}", output).into());
        }

        let output = Command::new("sudo")
            .arg("update-ca-certificates")
            .output()?;
        if !output.status.success() {
            return Err(format!("Failed to update CA certificates: {:?}", output).into());
        }
        Ok(())
    }
}

pub fn install_cert() -> Result<(), Box<dyn Error>> {
    let cert_path = "src/proxylea_cert.crt";
    
    if cfg!(target_os = "windows") {
        WindowsCertManager.install_cert(cert_path)?;
    } else if cfg!(target_os = "macos") {
        MacOSCertManager.install_cert(cert_path)?;
    } else if cfg!(target_os = "linux") {
        LinuxCertManager.install_cert(cert_path)?;
    } else {
        return Err("Unsupported operating system".into());
    }

    println!("Certificate installed successfully.");
    Ok(())
}

pub fn delete_cert() -> Result<(), Box<dyn Error>> {
    let cert_path = "src/proxylea_cert.crt";

    if cfg!(target_os = "windows") {
        WindowsCertManager.delete_cert(cert_path)?;
    } else if cfg!(target_os = "macos") {
        MacOSCertManager.delete_cert("proxylea_cert")?;
    } else if cfg!(target_os = "linux") {
        LinuxCertManager.delete_cert(cert_path)?;
    } else {
        return Err("Unsupported operating system".into());
    }

    println!("Certificate deleted successfully.");
    Ok(())
}

pub fn check_cert() -> Result<bool, Box<dyn Error>> {
    let cert_path = "src/proxylea_cert.crt";

    let is_installed = if cfg!(target_os = "windows") {
        WindowsCertManager.is_cert_installed(cert_path)?
    } else if cfg!(target_os = "macos") {
        MacOSCertManager.is_cert_installed("proxylea_cert")?
    } else if cfg!(target_os = "linux") {
        LinuxCertManager.is_cert_installed(cert_path)?
    } else {
        return Err("Unsupported operating system".into());
    };

    if is_installed {
        return Ok(true);
    } 
    Ok(false)
}
