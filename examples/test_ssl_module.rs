// Test SSL Certificate Extraction
// Tests the newly refactored async SSL module

use std::time::Duration;

#[path = "../src/ssl.rs"]
mod ssl;

#[tokio::main]
async fn main() {
    println!("\n🔐 Testing SSL Certificate Extraction\n");
    
    let targets = vec![
        ("github.com", 443),
        ("www.google.com", 443),
        ("nginx.org", 443),
        ("www.cloudflare.com", 443),
        ("192.168.18.35", 443),
    ];
    
    for (target, port) in targets {
        print!("Testing {}:{} ... ", target, port);
        
        match ssl::get_ssl_info(target, port, Duration::from_secs(5)).await {
            Some(info) => {
                println!("✅ SUCCESS");
                println!("  CN: {}", info.common_name.as_deref().unwrap_or("N/A"));
                println!("  Issuer: {}", info.issuer_cn.as_deref().unwrap_or("N/A"));
                println!("  Org: {}", info.organization.as_deref().unwrap_or("N/A"));
                println!("  Valid Until: {}", info.valid_until.as_deref().unwrap_or("N/A"));
                println!("  Days Until Expiry: {}", info.days_until_expiry.unwrap_or(0));
                println!("  Expired: {}", info.is_expired);
                println!("  Self-Signed: {}", info.is_self_signed);
                println!("  TLS Version: {}", info.tls_version.as_deref().unwrap_or("N/A"));
                println!("  SANs: {}", info.subject_alt_names.len());
                println!();
            }
            None => {
                println!("❌ FAILED");
                println!();
            }
        }
    }
}
