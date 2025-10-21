// TLS/SSL Certificate Parsing Module
// Extracts certificate information from HTTPS services
// Fully async implementation with tokio-rustls

use std::sync::Arc;
use std::time::Duration;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio_rustls::{TlsConnector, rustls};
use rustls::{ClientConfig, RootCertStore, ServerName};
use x509_parser::prelude::*;

/// SSL/TLS Certificate Information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSLInfo {
    /// Common Name (CN) from certificate
    pub common_name: Option<String>,
    /// Organization (O) from certificate
    pub organization: Option<String>,
    /// Organizational Unit (OU)
    pub organizational_unit: Option<String>,
    /// Country (C)
    pub country: Option<String>,
    /// Locality (L)
    pub locality: Option<String>,
    /// State/Province (ST)
    pub state: Option<String>,
    /// Subject Alternative Names (DNS names)
    pub subject_alt_names: Vec<String>,
    /// Issuer Common Name
    pub issuer_cn: Option<String>,
    /// Issuer Organization
    pub issuer_org: Option<String>,
    /// Certificate valid from (Not Before)
    pub valid_from: Option<String>,
    /// Certificate valid until (Not After)
    pub valid_until: Option<String>,
    /// Days until expiration
    pub days_until_expiry: Option<i64>,
    /// Is certificate expired?
    pub is_expired: bool,
    /// Is certificate self-signed?
    pub is_self_signed: bool,
    /// Serial number
    pub serial_number: Option<String>,
    /// Signature algorithm
    pub signature_algorithm: Option<String>,
    /// Public key algorithm
    pub public_key_algorithm: Option<String>,
    /// Key size in bits
    pub key_size: Option<usize>,
    /// TLS version negotiated
    pub tls_version: Option<String>,
    /// Cipher suite
    pub cipher_suite: Option<String>,
    /// HTTP/2 support via ALPN
    pub http2_support: bool,
    /// ALPN protocols negotiated
    pub alpn_protocol: Option<String>,
}

impl Default for SSLInfo {
    fn default() -> Self {
        Self {
            common_name: None,
            organization: None,
            organizational_unit: None,
            country: None,
            locality: None,
            state: None,
            subject_alt_names: Vec::new(),
            issuer_cn: None,
            issuer_org: None,
            valid_from: None,
            valid_until: None,
            days_until_expiry: None,
            is_expired: false,
            is_self_signed: false,
            serial_number: None,
            signature_algorithm: None,
            public_key_algorithm: None,
            key_size: None,
            tls_version: None,
            cipher_suite: None,
            http2_support: false,
            alpn_protocol: None,
        }
    }
}

/// Extract SSL/TLS certificate information from a target
pub async fn get_ssl_info(target: &str, port: u16, timeout: Duration) -> Option<SSLInfo> {
    // Attempt TLS connection with timeout
    tokio::time::timeout(timeout, get_ssl_info_internal(target, port))
        .await
        .ok()
        .flatten()
}

async fn get_ssl_info_internal(target: &str, port: u16) -> Option<SSLInfo> {
    // Create TLS config with root certificates and ALPN for HTTP/2 detection
    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    // Enable ALPN with HTTP/2 and HTTP/1.1 protocols
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let connector = TlsConnector::from(Arc::new(config));
    
    // Parse server name - rustls 0.21 syntax
    let server_name = match target.try_into() {
        Ok(name) => name,
        Err(_) => {
            // Fallback: try with explicit ServerName construction
            match ServerName::try_from(target) {
                Ok(n) => n,
                Err(_) => return None,
            }
        }
    };

    // Connect to target with async TcpStream
    let socket_addr = format!("{}:{}", target, port);
    let stream = match TcpStream::connect(&socket_addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to connect to {}: {}", socket_addr, e);
            return None;
        }
    };

    // Start async TLS handshake
    let mut tls_stream = match connector.connect(server_name, stream).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("TLS handshake failed for {}: {}", target, e);
            return None;
        }
    };
    
    // Send minimal HTTP request to trigger full handshake
    if let Err(e) = tls_stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await {
        eprintln!("Failed to write to TLS stream: {}", e);
        return None;
    }

    // Read some data to ensure handshake completes
    let mut buf = vec![0u8; 1024];
    let _ = tls_stream.read(&mut buf).await;

    // Extract certificate chain from TLS connection
    let (_, server_conn) = tls_stream.get_ref();
    let peer_certs = match server_conn.peer_certificates() {
        Some(certs) if !certs.is_empty() => certs,
        _ => return None,
    };

    // Parse first certificate (server cert)
    let cert_der = &peer_certs[0];
    let mut ssl_info = SSLInfo::default();

    // Get TLS version and cipher suite from connection
    if let Some(protocol_version) = server_conn.protocol_version() {
        ssl_info.tls_version = Some(format!("{:?}", protocol_version));
    }
    
    if let Some(cipher_suite) = server_conn.negotiated_cipher_suite() {
        ssl_info.cipher_suite = Some(format!("{:?}", cipher_suite.suite()));
    }
    
    // Check for HTTP/2 support via ALPN
    if let Some(alpn_protocol) = server_conn.alpn_protocol() {
        let protocol_str = String::from_utf8_lossy(alpn_protocol).to_string();
        ssl_info.alpn_protocol = Some(protocol_str.clone());
        ssl_info.http2_support = protocol_str == "h2";
    }

    // Parse X.509 certificate
    match parse_x509_certificate(cert_der.as_ref()) {
        Ok((_, cert)) => {
            // Extract Subject information
            for attr in cert.subject().iter_attributes() {
                // Try as_str first, fallback to raw bytes
                let value = if let Ok(s) = attr.attr_value().as_str() {
                    s.to_string()
                } else {
                    // Fallback: try to decode as UTF-8 from raw bytes  
                    String::from_utf8_lossy(attr.attr_value().data).to_string()
                };
                
                match attr.attr_type().to_id_string().as_str() {
                    "2.5.4.3" => ssl_info.common_name = Some(value), // CN
                    "2.5.4.10" => ssl_info.organization = Some(value), // O
                    "2.5.4.11" => ssl_info.organizational_unit = Some(value), // OU
                    "2.5.4.6" => ssl_info.country = Some(value), // C
                    "2.5.4.7" => ssl_info.locality = Some(value), // L
                    "2.5.4.8" => ssl_info.state = Some(value), // ST
                    _ => {}
                }
            }

            // Extract Issuer information
            for attr in cert.issuer().iter_attributes() {
                // Try as_str first, fallback to raw bytes
                let value = if let Ok(s) = attr.attr_value().as_str() {
                    s.to_string()
                } else {
                    String::from_utf8_lossy(attr.attr_value().data).to_string()
                };
                
                match attr.attr_type().to_id_string().as_str() {
                    "2.5.4.3" => ssl_info.issuer_cn = Some(value),
                    "2.5.4.10" => ssl_info.issuer_org = Some(value),
                    _ => {}
                }
            }

            // Check if self-signed (subject == issuer)
            ssl_info.is_self_signed = cert.subject() == cert.issuer();

            // Validity period
            let validity = cert.validity();
            ssl_info.valid_from = Some(format!("{}", validity.not_before));
            ssl_info.valid_until = Some(format!("{}", validity.not_after));

            // Calculate days until expiry
            let now = Utc::now().timestamp();
            let not_after_timestamp = validity.not_after.timestamp();
            let days_diff = (not_after_timestamp - now) / 86400; // seconds to days
            ssl_info.days_until_expiry = Some(days_diff);
            ssl_info.is_expired = days_diff < 0;

            // Serial number
            ssl_info.serial_number = Some(format!("{:X}", cert.serial));

            // Signature algorithm
            ssl_info.signature_algorithm = Some(format!("{:?}", cert.signature_algorithm.algorithm));

            // Public key info
            let public_key = cert.public_key();
            ssl_info.public_key_algorithm = Some(format!("{:?}", public_key.algorithm.algorithm));
            ssl_info.key_size = Some(public_key.subject_public_key.data.len() * 8);

            // Extract Subject Alternative Names (SANs)
            if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
                for name in &san_ext.value.general_names {
                    if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                        ssl_info.subject_alt_names.push(dns.to_string());
                    }
                }
            }

            Some(ssl_info)
        }
        Err(_) => None,
    }
}

/// Quick check if a port is likely HTTPS/TLS
pub fn is_likely_tls_port(port: u16) -> bool {
    matches!(port, 443 | 8443 | 8080 | 9443 | 10443 | 4443 | 3443 | 8444 | 8843)
}

/// Format SSL info for human-readable output
pub fn format_ssl_info(info: &SSLInfo) -> String {
    let mut output = String::new();
    
    output.push_str("🔐 TLS/SSL Certificate Information:\n");
    
    if let Some(cn) = &info.common_name {
        output.push_str(&format!("   CN: {}\n", cn));
    }
    
    if let Some(org) = &info.organization {
        output.push_str(&format!("   Organization: {}\n", org));
    }
    
    if !info.subject_alt_names.is_empty() {
        output.push_str(&format!("   SANs: {}\n", info.subject_alt_names.join(", ")));
    }
    
    if let Some(issuer) = &info.issuer_cn {
        output.push_str(&format!("   Issuer: {}\n", issuer));
    }
    
    if let Some(valid_until) = &info.valid_until {
        output.push_str(&format!("   Valid Until: {}\n", valid_until));
    }
    
    if let Some(days) = info.days_until_expiry {
        let status = if info.is_expired {
            "⚠️  EXPIRED"
        } else if days < 30 {
            "⚠️  Expiring Soon"
        } else {
            "✅ Valid"
        };
        output.push_str(&format!("   Expiry: {} ({} days)\n", status, days));
    }
    
    if info.is_self_signed {
        output.push_str("   ⚠️  Self-Signed Certificate\n");
    }
    
    if let Some(tls_ver) = &info.tls_version {
        output.push_str(&format!("   TLS Version: {}\n", tls_ver));
    }
    
    if let Some(cipher) = &info.cipher_suite {
        output.push_str(&format!("   Cipher: {}\n", cipher));
    }
    
    if let Some(key_size) = info.key_size {
        output.push_str(&format!("   Key Size: {} bits\n", key_size));
    }
    
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_likely_tls_port() {
        assert!(is_likely_tls_port(443));
        assert!(is_likely_tls_port(8443));
        assert!(!is_likely_tls_port(80));
        assert!(!is_likely_tls_port(22));
    }

    #[tokio::test]
    async fn test_ssl_info_google() {
        // Test against google.com:443 (usually available)
        if let Some(ssl_info) = get_ssl_info("google.com", 443, Duration::from_secs(10)).await {
            assert!(ssl_info.common_name.is_some());
            assert!(ssl_info.issuer_cn.is_some());
            assert!(!ssl_info.is_self_signed);
            println!("{}", format_ssl_info(&ssl_info));
        }
    }
}
