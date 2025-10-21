// HTTP/2 Detection Test
// Tests ALPN negotiation on various HTTPS servers

#[path = "../src/ssl.rs"]
mod ssl;

use std::time::Duration;

#[tokio::main]
async fn main() {
    println!("\n🔍 Testing HTTP/2 Detection via ALPN\n");

    let targets = vec![
        ("www.google.com", 443),
        ("www.cloudflare.com", 443),
        ("github.com", 443),
        ("www.microsoft.com", 443),
        ("nginx.org", 443),
    ];

    for (target, port) in targets {
        print!("Testing {}:{}...", target, port);
        
        match ssl::get_ssl_info(target, port, Duration::from_secs(5)).await {
            Some(info) => {
                if info.http2_support {
                    println!(" ✅ HTTP/2 SUPPORTED");
                    println!("  ALPN: {:?}", info.alpn_protocol);
                    println!("  TLS: {:?}", info.tls_version);
                } else {
                    println!(" ❌ HTTP/2 NOT SUPPORTED");
                    if let Some(alpn) = info.alpn_protocol {
                        println!("  ALPN: {}", alpn);
                    } else {
                        println!("  ALPN: None negotiated");
                    }
                }
            }
            None => {
                println!(" ❌ FAILED to connect");
            }
        }
        println!();
    }
}
