// src/main.rs

use clap::Parser;
use std::time::Duration;
use tokio::task;
use tokio::net::{TcpStream, UdpSocket};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use ipnet::Ipv4Net;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::Arc;
use regex;

// Dichiara i moduli
mod models;
mod stealth;
mod cve;

use models::*;
use stealth::*;
use cve::*; 

// --- CLI Configuration with clap ---

#[derive(Parser, Debug)]
#[command(author = "NextMap Dev Team", version, about = "🔍 Next generation network scanner with stealth capabilities and CVE detection.", long_about = None)]
struct Args {
    /// Target IP, IP range (e.g., 192.168.1.1-254) or CIDR (e.g., 192.168.1.0/24) to scan
    #[arg(short, long)]
    target: String,

    /// Ports to scan (e.g., "80,443,22-25")
    #[arg(short, long, default_value = "1-65535")]
    ports: String,
    
    /// Enable service detection and vulnerability analysis
    #[arg(short = 's', long, default_value_t = false)]
    service_scan: bool, 
    
    /// Enable OS fingerprinting
    #[arg(short = 'O', long, default_value_t = false)]
    os_scan: bool,
    
    /// Output format (human, json, yaml, xml, csv, md)
    #[arg(short, long, default_value = "human")]
    output_format: String,

    /// Connection timeout in milliseconds
    #[arg(short = 'T', long, default_value_t = 1000)]
    timeout: u64,

    /// Maximum concurrent tasks
    #[arg(short, long, default_value_t = 100)]
    concurrency: usize,

    /// Save output to file instead of stdout
    #[arg(short = 'f', long)]
    output_file: Option<String>,

    /// Enable UDP scanning in addition to TCP
    #[arg(short = 'U', long, default_value_t = false)]
    udp_scan: bool,

    /// UDP ports to scan (default: common UDP ports)
    #[arg(long, default_value = "53,67,68,69,123,135,137,138,139,161,162,445,500,514,1434,1900,4500,5353")]
    udp_ports: String,

    /// Rate limiting delay in milliseconds between scans
    #[arg(short = 'r', long, default_value_t = 0)]
    rate_limit: u64,

    /// Timing template: paranoid, sneaky, polite, normal, aggressive, insane
    #[arg(short = 'x', long, default_value = "normal")]
    timing_template: String,

    /// Enable stealth scanning mode (ghost, ninja, shadow)
    #[arg(long)]
    stealth_mode: Option<String>,

    /// Enable automatic CVE scanning
    #[arg(long, default_value_t = false)]
    cve_scan: bool,

    /// Custom CVE database path
    #[arg(long, default_value = "nextmap_cve.db")]
    cve_database: String,

    /// Update CVE database before scanning
    #[arg(long, default_value_t = false)]
    update_cve: bool,
}

// --- Support Functions ---

// Parse target input (singolo IP, range o CIDR)
fn parse_targets(target_input: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut targets = Vec::new();
    
    if target_input.contains('/') {
        // CIDR notation (es. 192.168.1.0/24)
        let network: Ipv4Net = target_input.parse()?;
        for ip in network.hosts() {
            targets.push(ip.to_string());
        }
    } else if target_input.contains('-') {
        // Range notation (es. 192.168.1.1-254)
        let parts: Vec<&str> = target_input.split('-').collect();
        if parts.len() == 2 {
            let base_ip = parts[0];
            let end_octet: u8 = parts[1].parse()?;
            
            // Estrai la base dell'IP (es. 192.168.1.)
            let ip_parts: Vec<&str> = base_ip.split('.').collect();
            if ip_parts.len() == 4 {
                let base = format!("{}.{}.{}.", ip_parts[0], ip_parts[1], ip_parts[2]);
                let start_octet: u8 = ip_parts[3].parse()?;
                
                for i in start_octet..=end_octet {
                    targets.push(format!("{}{}", base, i));
                }
            }
        }
    } else {
        // Singolo IP o hostname
        targets.push(target_input.to_string());
    }
    
    Ok(targets)
}

// Parse porte (supporta ranges come 22-25)
fn parse_ports(ports_input: &str) -> Result<Vec<u16>, Box<dyn std::error::Error>> {
    let mut ports = Vec::new();
    
    for part in ports_input.split(',') {
        let part = part.trim();
        if part.contains('-') {
            // Range di porte (es. 22-25)
            let range: Vec<&str> = part.split('-').collect();
            if range.len() == 2 {
                let start: u16 = range[0].parse()?;
                let end: u16 = range[1].parse()?;
                for port in start..=end {
                    ports.push(port);
                }
            }
        } else {
            // Porta singola
            ports.push(part.parse()?);
        }
    }
    
    Ok(ports)
}

// --- Core Functions for Real Scanning ---

// Real TCP scanning - attempts to connect to the port
async fn run_scan_syn(target: &str, port: u16, timeout: Duration) -> Port {
    // Create socket address
    let socket_addr = format!("{}:{}", target, port);
    
    // Attempt TCP connection
    let mut port_result = Port {
        port_id: port,
        protocol: "tcp".to_string(),
        state: PortState::Closed,
        service_name: None,
        service_version: None,
        banner: None,
    };
    
    match tokio::time::timeout(timeout, TcpStream::connect(&socket_addr)).await {
        Ok(Ok(mut stream)) => {
            port_result.state = PortState::Open;
            
            // Try banner grabbing for common services
            port_result.banner = grab_banner(&mut stream, port, timeout).await;
        }
        Ok(Err(_)) => {
            port_result.state = PortState::Closed;
        }
        Err(_) => {
            port_result.state = PortState::Filtered;
        }
    }

    port_result
}

// UDP scanning - sends UDP packets and analyzes responses
async fn run_scan_udp(target: &str, port: u16, timeout: Duration) -> Port {
    let socket_addr = format!("{}:{}", target, port);
    
    let mut port_result = Port {
        port_id: port,
        protocol: "udp".to_string(),
        state: PortState::Closed,
        service_name: None,
        service_version: None,
        banner: None,
    };
    
    // Create local UDP socket
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await {
        // Specific payloads for common UDP services
        let payload: &[u8] = match port {
            53 => b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01", // DNS query
            161 => b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00", // SNMP
            67 | 68 => b"\x01\x01\x06\x00\x00\x00\x3d\x1d\x00\x00\x00\x00\x00\x00\x00\x00", // DHCP discover
            _ => b"NextMap UDP Probe\n", // Generic probe
        };
        
        // Send UDP probe
        match tokio::time::timeout(timeout, socket.send_to(payload, &socket_addr)).await {
            Ok(Ok(_)) => {
                // Wait for response
                let mut buffer = [0; 1024];
                match tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buffer)).await {
                    Ok(Ok((n, _))) if n > 0 => {
                        port_result.state = PortState::Open;
                        let response = String::from_utf8_lossy(&buffer[..n]);
                        if !response.trim().is_empty() {
                            port_result.banner = Some(response.lines().next().unwrap_or("").trim().to_string());
                        }
                    }
                    _ => {
                        // No response = probably filtered or closed
                        port_result.state = PortState::Filtered;
                    }
                }
            }
            _ => {
                port_result.state = PortState::Filtered;
            }
        }
    }
    
    port_result
}

// Advanced OS fingerprinting based on TCP characteristics
async fn detect_os(_target: &str, open_ports: &[Port]) -> Option<OSDetails> {
    if open_ports.is_empty() {
        return None;
    }
    
    // Analyze service patterns to infer OS
    let services: Vec<&str> = open_ports.iter()
        .filter_map(|p| p.service_name.as_deref())
        .collect();
    
    let (os_vendor, os_family, ttl, confidence) = analyze_service_patterns(&services);
    
    Some(OSDetails {
        os_vendor: Some(os_vendor),
        os_family: Some(os_family),
        accuracy: confidence,
        ttl_hop_distance: ttl,
    })
}

// Analyze service patterns to infer OS
fn analyze_service_patterns(services: &[&str]) -> (String, String, u8, u8) {
    let has_ssh = services.contains(&"ssh");
    let has_http = services.contains(&"http") || services.contains(&"https");
    let has_smb = services.iter().any(|&s| s.contains("microsoft") || s.contains("netbios"));
    let has_rdp = services.contains(&"ms-wbt-server");
    let has_mysql = services.contains(&"mysql");
    let has_apache = services.iter().any(|&s| s.contains("apache"));
    let has_nginx = services.iter().any(|&s| s.contains("nginx"));
    
    // Detection logic based on service combinations
    if has_rdp || has_smb {
        ("Microsoft".to_string(), "Windows".to_string(), 128, 85)
    } else if has_ssh && has_apache && has_mysql {
        ("Linux".to_string(), "Ubuntu/CentOS".to_string(), 64, 75)
    } else if has_ssh && has_nginx {
        ("Linux".to_string(), "Debian/Ubuntu".to_string(), 64, 70)
    } else if has_ssh && has_http {
        ("Linux".to_string(), "Linux".to_string(), 64, 60)
    } else if has_http && !has_ssh {
        ("Unknown".to_string(), "Embedded/Appliance".to_string(), 255, 45)
    } else {
        ("Unknown".to_string(), "Unknown".to_string(), 64, 30)
    }
}

// Banner grabbing per identificazione servizi
async fn grab_banner(stream: &mut TcpStream, port: u16, timeout: Duration) -> Option<String> {
    let mut buffer = [0; 1024];
    
    // Per alcuni servizi, dobbiamo inviare un comando
    let probe = match port {
        80 | 8080 => Some("GET / HTTP/1.0\r\n\r\n"),
        21 => None, // FTP invia banner automaticamente
        22 => None, // SSH invia banner automaticamente  
        25 => None, // SMTP invia banner automaticamente
        110 => None, // POP3 invia banner automaticamente
        143 => None, // IMAP invia banner automaticamente
        _ => None,
    };
    
    // Invia probe se necessario
    if let Some(probe_cmd) = probe {
        if stream.write_all(probe_cmd.as_bytes()).await.is_err() {
            return None;
        }
    }
    
    // Leggi la risposta
    match tokio::time::timeout(timeout, stream.read(&mut buffer)).await {
        Ok(Ok(n)) if n > 0 => {
            let banner = String::from_utf8_lossy(&buffer[..n]);
            let cleaned = banner.lines().next()?.trim();
            if !cleaned.is_empty() {
                Some(cleaned.to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

// Analizza le porte aperte e identifica i servizi
async fn analyze_open_port(mut port: Port) -> (Port, Vec<Vulnerability>) {
    let mut vulns = Vec::new();
    
    if port.state == PortState::Open {
        // Analisi banner se disponibile
        if let Some(ref banner) = port.banner {
            // Estrai informazioni dal banner
            let banner_lower = banner.to_lowercase();
            
            if banner_lower.contains("apache") {
                port.service_name = Some("http".to_string());
                if let Some(version) = extract_version(&banner_lower, "apache") {
                    port.service_version = Some(version);
                }
            } else if banner_lower.contains("nginx") {
                port.service_name = Some("http".to_string());
                if let Some(version) = extract_version(&banner_lower, "nginx") {
                    port.service_version = Some(version);
                }
            } else if banner_lower.contains("ssh") {
                port.service_name = Some("ssh".to_string());
                if let Some(version) = extract_version(&banner_lower, "openssh") {
                    port.service_version = Some(version);
                }
            } else if banner_lower.contains("ftp") {
                port.service_name = Some("ftp".to_string());
            }
        }
        
        // Identificazione servizi basata su porte standard se non identificato dal banner
        if port.service_name.is_none() {
            match (port.port_id, port.protocol.as_str()) {
                // Servizi TCP
                (21, "tcp") => {
                    port.service_name = Some("ftp".to_string());
                    port.service_version = Some("Unknown".to_string());
                }
                (22, "tcp") => {
                    port.service_name = Some("ssh".to_string());
                    port.service_version = Some("OpenSSH".to_string());
                }
                (23, "tcp") => {
                    port.service_name = Some("telnet".to_string());
                    port.service_version = Some("Unknown".to_string());
                    vulns.push(Vulnerability {
                        cve_id: "TELNET-PLAINTEXT".to_string(),
                        severity: "High".to_string(),
                        description_short: "Telnet transmits data in plaintext - use SSH instead".to_string(),
                        service_port: 23,
                    });
                }
                (25, "tcp") => {
                    port.service_name = Some("smtp".to_string());
                    port.service_version = Some("Unknown".to_string());
                }
                (53, "tcp") => {
                    port.service_name = Some("domain".to_string());
                    port.service_version = Some("DNS".to_string());
                }
                (80 | 8080, "tcp") => {
                    port.service_name = Some("http".to_string());
                    port.service_version = Some("HTTP Server".to_string());
                    vulns.push(Vulnerability {
                        cve_id: "HTTP-UNENCRYPTED".to_string(),
                        severity: "Medium".to_string(),
                        description_short: "Unencrypted HTTP traffic - consider HTTPS".to_string(),
                        service_port: port.port_id,
                    });
                }
                (110, "tcp") => {
                    port.service_name = Some("pop3".to_string());
                    port.service_version = Some("POP3".to_string());
                }
                (143, "tcp") => {
                    port.service_name = Some("imap".to_string());
                    port.service_version = Some("IMAP".to_string());
                }
                (443 | 8443, "tcp") => {
                    port.service_name = Some("https".to_string());
                    port.service_version = Some("HTTPS Server".to_string());
                }
                (993, "tcp") => {
                    port.service_name = Some("imaps".to_string());
                    port.service_version = Some("IMAP over SSL".to_string());
                }
                (995, "tcp") => {
                    port.service_name = Some("pop3s".to_string());
                    port.service_version = Some("POP3 over SSL".to_string());
                }
                (3389, "tcp") => {
                    port.service_name = Some("ms-wbt-server".to_string());
                    port.service_version = Some("Remote Desktop".to_string());
                    vulns.push(Vulnerability {
                        cve_id: "RDP-EXPOSURE".to_string(),
                        severity: "High".to_string(),
                        description_short: "RDP exposed to Internet - consider VPN".to_string(),
                        service_port: 3389,
                    });
                }
                (5432, "tcp") => {
                    port.service_name = Some("postgresql".to_string());
                    port.service_version = Some("PostgreSQL".to_string());
                }
                (3306, "tcp") => {
                    port.service_name = Some("mysql".to_string());
                    port.service_version = Some("MySQL".to_string());
                }
                (1433, "tcp") => {
                    port.service_name = Some("ms-sql-s".to_string());
                    port.service_version = Some("Microsoft SQL Server".to_string());
                }
                (5984, "tcp") => {
                    port.service_name = Some("couchdb".to_string());
                    port.service_version = Some("CouchDB".to_string());
                }
                (6379, "tcp") => {
                    port.service_name = Some("redis".to_string());
                    port.service_version = Some("Redis".to_string());
                }
                (27017, "tcp") => {
                    port.service_name = Some("mongodb".to_string());
                    port.service_version = Some("MongoDB".to_string());
                }
                
                // Servizi UDP
                (53, "udp") => {
                    port.service_name = Some("domain".to_string());
                    port.service_version = Some("DNS".to_string());
                }
                (67, "udp") => {
                    port.service_name = Some("dhcps".to_string());
                    port.service_version = Some("DHCP Server".to_string());
                }
                (68, "udp") => {
                    port.service_name = Some("dhcpc".to_string());
                    port.service_version = Some("DHCP Client".to_string());
                }
                (69, "udp") => {
                    port.service_name = Some("tftp".to_string());
                    port.service_version = Some("Trivial FTP".to_string());
                }
                (123, "udp") => {
                    port.service_name = Some("ntp".to_string());
                    port.service_version = Some("Network Time Protocol".to_string());
                }
                (161, "udp") => {
                    port.service_name = Some("snmp".to_string());
                    port.service_version = Some("SNMP Agent".to_string());
                    vulns.push(Vulnerability {
                        cve_id: "SNMP-DEFAULT-COMMUNITY".to_string(),
                        severity: "Medium".to_string(),
                        description_short: "SNMP may use default community strings".to_string(),
                        service_port: 161,
                    });
                }
                (162, "udp") => {
                    port.service_name = Some("snmptrap".to_string());
                    port.service_version = Some("SNMP Trap".to_string());
                }
                (500, "udp") => {
                    port.service_name = Some("isakmp".to_string());
                    port.service_version = Some("IPSec IKE".to_string());
                }
                (514, "udp") => {
                    port.service_name = Some("syslog".to_string());
                    port.service_version = Some("Syslog".to_string());
                }
                (1900, "udp") => {
                    port.service_name = Some("upnp".to_string());
                    port.service_version = Some("UPnP".to_string());
                }
                
                _ => {
                    port.service_name = Some("unknown".to_string());
                    port.service_version = Some("Unknown".to_string());
                }
            }
        }
    }
    
    (port, vulns)
}

// Funzione helper per estrarre versioni dai banner
fn extract_version(banner: &str, service: &str) -> Option<String> {
    let patterns = [
        format!("{}/([\\d\\.]+)", service),
        format!("{} ([\\d\\.]+)", service),
        format!("{}\\s+([\\d\\.]+)", service),
    ];
    
    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(captures) = re.captures(banner) {
                if let Some(version) = captures.get(1) {
                    return Some(format!("{} {}", service, version.as_str()));
                }
            }
        }
    }
    None
}

// Funzioni per formati di output
fn generate_xml_output(scan_results: &ScanResult) -> String {
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<nmaprun>\n");
    xml.push_str(&format!("  <scaninfo type=\"nextmap\" protocol=\"tcp+udp\" numservices=\"{}\" />\n", 
        scan_results.hosts.iter().map(|h| h.ports.len()).sum::<usize>()));
    xml.push_str(&format!("  <verbose level=\"0\" />\n"));
    xml.push_str(&format!("  <debugging level=\"0\" />\n"));
    
    for host in &scan_results.hosts {
        xml.push_str(&format!("  <host starttime=\"{}\" endtime=\"{}\">\n", 
            scan_results.timestamp, scan_results.timestamp));
        xml.push_str(&format!("    <status state=\"{}\" reason=\"\" />\n", 
            match host.status {
                HostStatus::Up => "up",
                HostStatus::Down => "down",
                HostStatus::Filtered => "filtered",
            }));
        xml.push_str(&format!("    <address addr=\"{}\" addrtype=\"ipv4\" />\n", host.ip_address));
        
        if let Some(ref hostname) = host.hostname {
            xml.push_str(&format!("    <hostnames><hostname name=\"{}\" type=\"PTR\" /></hostnames>\n", hostname));
        }
        
        xml.push_str("    <ports>\n");
        for port in &host.ports {
            xml.push_str(&format!("      <port protocol=\"{}\" portid=\"{}\">\n", port.protocol, port.port_id));
            xml.push_str(&format!("        <state state=\"{}\" reason=\"\" />\n", 
                match port.state {
                    PortState::Open => "open",
                    PortState::Closed => "closed",
                    PortState::Filtered => "filtered",
                    PortState::OpenFiltered => "open|filtered",
                }));
            if let Some(ref service) = port.service_name {
                xml.push_str(&format!("        <service name=\"{}\" ", service));
                if let Some(ref version) = port.service_version {
                    xml.push_str(&format!("version=\"{}\" ", version));
                }
                xml.push_str("/>\n");
            }
            xml.push_str("      </port>\n");
        }
        xml.push_str("    </ports>\n");
        
        if let Some(ref os) = host.os_details {
            xml.push_str("    <os>\n");
            if let Some(ref vendor) = os.os_vendor {
                xml.push_str(&format!("      <osmatch name=\"{}\" accuracy=\"{}\" />\n", vendor, os.accuracy));
            }
            xml.push_str("    </os>\n");
        }
        
        xml.push_str("  </host>\n");
    }
    
    xml.push_str(&format!("  <runstats><finished time=\"{}\" timestr=\"{}\" elapsed=\"{:.2}\" /></runstats>\n", 
        scan_results.timestamp, scan_results.timestamp, scan_results.duration_ms as f64 / 1000.0));
    xml.push_str("</nmaprun>\n");
    xml
}

fn generate_csv_output(scan_results: &ScanResult) -> String {
    let mut csv = String::new();
    csv.push_str("IP,Hostname,Port,Protocol,State,Service,Version,Banner\n");
    
    for host in &scan_results.hosts {
        for port in &host.ports {
            csv.push_str(&format!("\"{}\",\"{}\",{},\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
                host.ip_address,
                host.hostname.as_deref().unwrap_or(""),
                port.port_id,
                port.protocol,
                match port.state {
                    PortState::Open => "open",
                    PortState::Closed => "closed", 
                    PortState::Filtered => "filtered",
                    PortState::OpenFiltered => "open|filtered",
                },
                port.service_name.as_deref().unwrap_or(""),
                port.service_version.as_deref().unwrap_or(""),
                port.banner.as_deref().unwrap_or("").replace("\"", "\\\"")
            ));
        }
    }
    
    csv
}

// Helper function per centrare il testo
fn center_text(text: &str, width: usize) -> String {
    let text_len = text.len();
    if text_len >= width {
        return text.to_string();
    }
    let padding = (width - text_len) / 2;
    format!("{}{}{}", " ".repeat(padding), text, " ".repeat(width - text_len - padding))
}

// Output human-readable (default)
fn generate_human_output(scan_results: &ScanResult) -> String {
    let mut output = String::new();
    
    // Header con informazioni scan
    output.push_str(&format!("{}\n", "═".repeat(60).cyan()));
    output.push_str(&format!("{}\n", center_text("🔍 NEXTMAP SCAN RESULTS", 60).cyan().bold()));
    output.push_str(&format!("{}\n", "═".repeat(60).cyan()));
    
    output.push_str(&format!("🕒 Scan started: {}\n", scan_results.timestamp.bright_yellow()));
    output.push_str(&format!("⏱️  Duration: {:.2}s\n", scan_results.duration_ms as f64 / 1000.0));
    output.push_str(&format!("📋 Command: {}\n", scan_results.command.bright_blue()));
    output.push_str(&format!("🎯 Hosts scanned: {}\n\n", scan_results.hosts.len().to_string().green()));
    
    let mut total_open_ports = 0;
    let mut total_vulnerabilities = 0;
    
    for host in &scan_results.hosts {
        let open_ports: Vec<&Port> = host.ports.iter().filter(|p| p.state == PortState::Open).collect();
        let filtered_ports: Vec<&Port> = host.ports.iter().filter(|p| p.state == PortState::Filtered).collect();
        
        total_open_ports += open_ports.len();
        total_vulnerabilities += host.vulnerabilities.len();
        
        // Header host
        output.push_str(&format!("{}\n", "─".repeat(50).blue()));
        output.push_str(&format!("🖥️  HOST: {} ", host.ip_address.bright_cyan().bold()));
        
        if let Some(ref hostname) = host.hostname {
            output.push_str(&format!("({})", hostname.yellow()));
        }
        
        match host.status {
            HostStatus::Up => output.push_str(&format!(" [{}]\n", "UP".green().bold())),
            HostStatus::Down => output.push_str(&format!(" [{}]\n", "DOWN".red().bold())),
            HostStatus::Filtered => output.push_str(&format!(" [{}]\n", "FILTERED".yellow().bold())),
        }
        
        // OS Information
        if let Some(ref os) = host.os_details {
            if let Some(ref vendor) = os.os_vendor {
                output.push_str(&format!("💻 OS: {} ", vendor.magenta()));
                if let Some(ref family) = os.os_family {
                    output.push_str(&format!("{} ", family.magenta()));
                }
                output.push_str(&format!("({}% confidence)\n", os.accuracy.to_string().yellow()));
            }
        }
        
        // Porte aperte
        if !open_ports.is_empty() {
            output.push_str(&format!("\n🟢 OPEN PORTS ({}):\n", open_ports.len().to_string().green()));
            
            for port in &open_ports {
                output.push_str(&format!("   {} ", port.port_id.to_string().bright_green()));
                output.push_str(&format!("{:<6} ", port.protocol.cyan()));
                
                if let Some(ref service) = port.service_name {
                    output.push_str(&format!("{:<15} ", service.yellow()));
                    if let Some(ref version) = port.service_version {
                        output.push_str(&format!("{:<20} ", version.white()));
                    }
                } else {
                    output.push_str(&format!("{:<35} ", "unknown".dimmed()));
                }
                
                if let Some(ref banner) = port.banner {
                    let short_banner = if banner.len() > 40 {
                        format!("{}...", &banner[..37])
                    } else {
                        banner.clone()
                    };
                    output.push_str(&format!("{}", short_banner.dimmed()));
                }
                output.push_str("\n");
            }
        }
        
        // Porte filtrate
        if !filtered_ports.is_empty() {
            output.push_str(&format!("\n🟡 FILTERED PORTS ({}): ", filtered_ports.len().to_string().yellow()));
            let filtered_list: Vec<String> = filtered_ports.iter().map(|p| p.port_id.to_string()).collect();
            output.push_str(&format!("{}\n", filtered_list.join(", ").dimmed()));
        }
        
        // Vulnerabilità
        if !host.vulnerabilities.is_empty() {
            output.push_str(&format!("\n🚨 VULNERABILITIES ({}):\n", host.vulnerabilities.len().to_string().red()));
            
            for vuln in &host.vulnerabilities {
                let severity_color = match vuln.severity.as_str() {
                    "Critical" => vuln.severity.red().bold(),
                    "High" => vuln.severity.red(),
                    "Medium" => vuln.severity.yellow(),
                    "Low" => vuln.severity.green(),
                    _ => vuln.severity.white(),
                };
                
                output.push_str(&format!("   🔴 {} [{}] - Port {}\n", 
                    vuln.cve_id.bright_red(),
                    severity_color,
                    vuln.service_port.to_string().cyan()
                ));
                output.push_str(&format!("      {}\n", vuln.description_short.dimmed()));
            }
        }
        
        output.push_str("\n");
    }
    
    // Summary footer
    output.push_str(&format!("{}\n", "═".repeat(60).cyan()));
    output.push_str(&format!("{}\n", center_text("📊 SCAN SUMMARY", 60).cyan().bold()));
    output.push_str(&format!("{}\n", "═".repeat(60).cyan()));
    output.push_str(&format!("🎯 Total hosts: {}\n", scan_results.hosts.len().to_string().green()));
    output.push_str(&format!("🟢 Open ports: {}\n", total_open_ports.to_string().green()));
    output.push_str(&format!("🚨 Vulnerabilities found: {}\n", total_vulnerabilities.to_string().red()));
    output.push_str(&format!("⚡ Scan completed in {:.2} seconds\n", scan_results.duration_ms as f64 / 1000.0));
    output.push_str(&format!("{}\n", "═".repeat(60).cyan()));
    
    output
}

// Output Markdown per documentazione e report
fn generate_markdown_output(scan_results: &ScanResult) -> String {
    let mut md = String::new();
    
    // Title and metadata
    md.push_str("# 🔍 NextMap Network Scan Report\n\n");
    
    // Scan information table
    md.push_str("## 📋 Scan Information\n\n");
    md.push_str("| Field | Value |\n");
    md.push_str("|-------|-------|\n");
    md.push_str(&format!("| **Timestamp** | `{}` |\n", scan_results.timestamp));
    md.push_str(&format!("| **Duration** | `{:.2}s` |\n", scan_results.duration_ms as f64 / 1000.0));
    md.push_str(&format!("| **Command** | `{}` |\n", scan_results.command));
    md.push_str(&format!("| **Hosts Scanned** | `{}` |\n", scan_results.hosts.len()));
    md.push_str("\n");
    
    let mut total_open_ports = 0;
    let mut total_vulnerabilities = 0;
    let mut up_hosts = 0;
    
    // Calculate totals
    for host in &scan_results.hosts {
        if matches!(host.status, HostStatus::Up) {
            up_hosts += 1;
        }
        total_open_ports += host.ports.iter().filter(|p| p.state == PortState::Open).count();
        total_vulnerabilities += host.vulnerabilities.len();
    }
    
    // Summary section
    md.push_str("## 📊 Scan Summary\n\n");
    md.push_str(&format!("- 🎯 **Total Hosts**: {}\n", scan_results.hosts.len()));
    md.push_str(&format!("- 🟢 **Hosts Up**: {}\n", up_hosts));
    md.push_str(&format!("- 🔓 **Open Ports**: {}\n", total_open_ports));
    md.push_str(&format!("- 🚨 **Vulnerabilities**: {}\n", total_vulnerabilities));
    md.push_str("\n");
    
    // Detailed results per host
    md.push_str("## 🖥️ Host Details\n\n");
    
    for (i, host) in scan_results.hosts.iter().enumerate() {
        md.push_str(&format!("### Host {} - `{}`\n\n", i + 1, host.ip_address));
        
        // Host status badge
        let status_badge = match host.status {
            HostStatus::Up => "![Status](https://img.shields.io/badge/Status-UP-green)",
            HostStatus::Down => "![Status](https://img.shields.io/badge/Status-DOWN-red)",
            HostStatus::Filtered => "![Status](https://img.shields.io/badge/Status-FILTERED-yellow)",
        };
        md.push_str(&format!("{}\n\n", status_badge));
        
        // Basic info
        if let Some(ref hostname) = host.hostname {
            md.push_str(&format!("**Hostname**: `{}`\n\n", hostname));
        }
        
        // OS Information
        if let Some(ref os) = host.os_details {
            md.push_str("#### 💻 Operating System\n\n");
            
            if let Some(ref vendor) = os.os_vendor {
                md.push_str(&format!("- **Vendor**: {}\n", vendor));
            }
            if let Some(ref family) = os.os_family {
                md.push_str(&format!("- **Family**: {}\n", family));
            }
            md.push_str(&format!("- **Confidence**: {}%\n", os.accuracy));
            md.push_str(&format!("- **TTL Distance**: {}\n\n", os.ttl_hop_distance));
        }
        
        // Ports section
        let open_ports: Vec<&Port> = host.ports.iter().filter(|p| p.state == PortState::Open).collect();
        let closed_ports: Vec<&Port> = host.ports.iter().filter(|p| p.state == PortState::Closed).collect();
        let filtered_ports: Vec<&Port> = host.ports.iter().filter(|p| p.state == PortState::Filtered).collect();
        
        if !host.ports.is_empty() {
            md.push_str("#### 🔍 Port Scan Results\n\n");
            
            // Open ports table
            if !open_ports.is_empty() {
                md.push_str("##### 🟢 Open Ports\n\n");
                md.push_str("| Port | Protocol | Service | Version | Banner |\n");
                md.push_str("|------|----------|---------|---------|--------|\n");
                
                for port in &open_ports {
                    let service = port.service_name.as_deref().unwrap_or("unknown");
                    let version = port.service_version.as_deref().unwrap_or("N/A");
                    let banner = port.banner.as_deref()
                        .map(|b| if b.len() > 50 { format!("{}...", &b[..47]) } else { b.to_string() })
                        .unwrap_or_else(|| "N/A".to_string());
                    
                    md.push_str(&format!("| `{}` | `{}` | `{}` | `{}` | `{}` |\n", 
                        port.port_id, port.protocol, service, version, banner));
                }
                md.push_str("\n");
            }
            
            // Filtered ports
            if !filtered_ports.is_empty() {
                md.push_str("##### 🟡 Filtered Ports\n\n");
                let filtered_list: Vec<String> = filtered_ports.iter()
                    .map(|p| format!("`{}/{}`", p.port_id, p.protocol))
                    .collect();
                md.push_str(&format!("{}\n\n", filtered_list.join(", ")));
            }
            
            // Closed ports summary
            if !closed_ports.is_empty() {
                md.push_str(&format!("##### 🔴 Closed Ports: {} ports\n\n", closed_ports.len()));
            }
        }
        
        // Vulnerabilities
        if !host.vulnerabilities.is_empty() {
            md.push_str("#### 🚨 Security Vulnerabilities\n\n");
            
            for vuln in &host.vulnerabilities {
                let severity_badge = match vuln.severity.as_str() {
                    "Critical" => "![Critical](https://img.shields.io/badge/Severity-CRITICAL-red)",
                    "High" => "![High](https://img.shields.io/badge/Severity-HIGH-orange)",
                    "Medium" => "![Medium](https://img.shields.io/badge/Severity-MEDIUM-yellow)",
                    "Low" => "![Low](https://img.shields.io/badge/Severity-LOW-green)",
                    _ => &format!("![{}](https://img.shields.io/badge/Severity-{}-lightgrey)", vuln.severity, vuln.severity.to_uppercase()),
                };
                
                md.push_str(&format!("##### {} `{}` - Port {}\n\n", severity_badge, vuln.cve_id, vuln.service_port));
                md.push_str(&format!("{}\n\n", vuln.description_short));
            }
        }
        
        md.push_str("---\n\n");
    }
    
    // Footer
    md.push_str("## 🛡️ Recommendations\n\n");
    
    if total_vulnerabilities > 0 {
        md.push_str("### ⚠️ Security Issues Found\n\n");
        md.push_str(&format!("- **{} vulnerabilities** were detected during this scan\n", total_vulnerabilities));
        md.push_str("- Review each vulnerability and apply appropriate patches\n");
        md.push_str("- Consider implementing additional security controls\n");
        md.push_str("- Schedule regular security scans\n\n");
    }
    
    md.push_str("### 🔒 General Security\n\n");
    md.push_str("- Close unnecessary open ports\n");
    md.push_str("- Keep all services updated to latest versions\n");
    md.push_str("- Implement proper firewall rules\n");
    md.push_str("- Monitor network traffic regularly\n");
    md.push_str("- Use strong authentication mechanisms\n\n");
    
    md.push_str("---\n\n");
    md.push_str(&format!("*Report generated by NextMap on {}*\n", scan_results.timestamp));
    
    md
}

// Configurazione timing templates (simile a Nmap)
fn get_timing_config(template: &str) -> (u64, usize, u64) {
    // Returns: (timeout_ms, max_concurrency, rate_limit_ms)
    match template {
        "paranoid" => (10000, 1, 300000),      // 10s timeout, 1 concurrent, 5min between scans
        "sneaky" => (5000, 5, 15000),          // 5s timeout, 5 concurrent, 15s between scans  
        "polite" => (3000, 10, 400),           // 3s timeout, 10 concurrent, 400ms between scans
        "normal" => (1000, 100, 0),            // 1s timeout, 100 concurrent, no delay
        "aggressive" => (500, 200, 0),         // 500ms timeout, 200 concurrent, no delay
        "insane" => (100, 500, 0),             // 100ms timeout, 500 concurrent, no delay
        _ => (1000, 100, 0),                   // Default to normal
    }
}

// --- Funzione Main (Punto di Ingresso) ---

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    // Parse targets e porte usando le nuove funzioni
    let targets = parse_targets(&args.target)?;
    let tcp_ports = parse_ports(&args.ports)?;
    let udp_ports = if args.udp_scan {
        parse_ports(&args.udp_ports)?
    } else {
        Vec::new()
    };
    
    let start_time = chrono::Utc::now();
    
    // Configurazione stealth
    let stealth_config = if let Some(stealth_mode) = &args.stealth_mode {
        Some(get_stealth_preset(stealth_mode))
    } else {
        None
    };
    
    // CVE Scanning initialization
    let cve_db = if args.cve_scan {
        println!("🛡️ Initializing CVE database...");
        let db = initialize_cve_database(&args.cve_database).await?;
        
        if args.update_cve {
            println!("📡 Updating CVE database from NIST...");
            match db.update_database().await {
                Ok(count) => println!("✅ Updated with {} new CVEs", count),
                Err(e) => println!("⚠️ CVE update failed: {} (using cached data)", e),
            }
        }
        
        let stats = db.get_statistics()?;
        println!("📊 CVE Database: {} total vulnerabilities", stats.total_cves);
        Some(db)
    } else {
        None
    };
    
    // Configurazione timing
    let (template_timeout, template_concurrency, template_rate_limit) = get_timing_config(&args.timing_template);
    let timeout = Duration::from_millis(if args.timeout == 1000 { template_timeout } else { args.timeout });
    let concurrency = if args.concurrency == 100 { template_concurrency } else { args.concurrency };
    let rate_limit = if args.rate_limit == 0 { template_rate_limit } else { args.rate_limit };
    
    println!("{}", format!("🚀 Starting NextMap scan...").cyan().bold());
    
    if let Some(stealth_mode) = &args.stealth_mode {
        println!("🥷 Stealth mode: {} enabled", stealth_mode.bright_magenta());
    }
    
    if args.cve_scan {
        println!("🛡️ CVE scanning: {}", "ENABLED".green());
    }
    
    println!("📍 Targets: {} hosts", targets.len().to_string().green());
    println!("🔍 TCP Ports: {} ports", tcp_ports.len().to_string().green());
    if args.udp_scan {
        println!("🔍 UDP Ports: {} ports", udp_ports.len().to_string().yellow());
    }
    
    // Avviso per scan di molte porte
    if tcp_ports.len() > 1000 {
        println!("⚠️  {}: Scanning {} TCP ports. This may take several minutes.", 
                 "WARNING".yellow().bold(), 
                 tcp_ports.len().to_string().red());
        println!("💡 {}: Use --ports \"1-1000\" for faster results or add --timing-template aggressive", 
                 "TIP".cyan().bold());
    }
    
    println!("⏱️  Timeout: {}ms | Concurrency: {} | Rate limit: {}ms", 
             timeout.as_millis().to_string().yellow(),
             concurrency.to_string().cyan(),
             rate_limit.to_string().magenta());
    println!("🎯 Timing template: {}", args.timing_template.bright_blue());
    
    // Progress bar setup
    let total_scans = targets.len() * (tcp_ports.len() + udp_ports.len());
    let pb = ProgressBar::new(total_scans as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .unwrap()
        .progress_chars("=>-"));
    
    let mut all_hosts = Vec::new();
    
    // Semaforo per limitare la concorrenza
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    
    for target_ip in targets {
        let mut tasks = Vec::new();
        let service_scan = args.service_scan;
        
        // Scansione TCP
        for port in &tcp_ports {
            let ip_clone = target_ip.clone();
            let port = *port;
            let pb_clone = pb.clone();
            let sem_clone = semaphore.clone();
            let stealth_cfg = stealth_config.clone();
            
            tasks.push(task::spawn(async move {
                let _permit = sem_clone.acquire().await.unwrap();
                
                let result = if let Some(stealth_config) = &stealth_cfg {
                    // Modalità stealth
                    log_stealth_activity(&ip_clone, port, "TCP_STEALTH", stealth_config);
                    
                    let port_state = if stealth_config.fragment_packets {
                        fragmented_scan(&ip_clone, port, stealth_config, timeout).await
                            .unwrap_or(PortState::Filtered)
                    } else {
                        syn_stealth_scan(&ip_clone, port, stealth_config, timeout).await
                            .unwrap_or(PortState::Filtered)
                    };
                    
                    Port {
                        port_id: port,
                        protocol: "tcp".to_string(),
                        state: port_state,
                        service_name: None,
                        service_version: None,
                        banner: None,
                    }
                } else {
                    // Scansione normale
                    if rate_limit > 0 {
                        tokio::time::sleep(Duration::from_millis(rate_limit)).await;
                    }
                    run_scan_syn(&ip_clone, port, timeout).await
                };
                
                pb_clone.inc(1);
                
                if result.state == PortState::Open && service_scan {
                    analyze_open_port(result).await
                } else {
                    (result, Vec::new())
                }
            }));
        }
        
        // Scansione UDP se abilitata
        if args.udp_scan {
            for port in &udp_ports {
                let ip_clone = target_ip.clone();
                let port = *port;
                let pb_clone = pb.clone();
                let sem_clone = semaphore.clone();
                
                tasks.push(task::spawn(async move {
                    let _permit = sem_clone.acquire().await.unwrap();
                    
                    // Rate limiting
                    if rate_limit > 0 {
                        tokio::time::sleep(Duration::from_millis(rate_limit)).await;
                    }
                    
                    let result = run_scan_udp(&ip_clone, port, timeout).await;
                    pb_clone.inc(1);
                    
                    if result.state == PortState::Open && service_scan {
                        analyze_open_port(result).await
                    } else {
                        (result, Vec::new())
                    }
                }));
            }
        }

        let mut host = Host {
            ip_address: target_ip.clone(),
            hostname: None,
            status: HostStatus::Up,
            ports: Vec::new(),
            os_details: None,
            vulnerabilities: Vec::new(),
        };

        // Raccolta risultati per questo host
        for task in tasks {
            match task.await {
                Ok((port_res, vulns)) => {
                    host.ports.push(port_res);
                    host.vulnerabilities.extend(vulns);
                }
                Err(e) => {
                    eprintln!("❌ Task failed: {}", e);
                }
            }
        }
        
        // OS Fingerprinting se richiesto
        if args.os_scan && !host.ports.is_empty() {
            let open_ports: Vec<&Port> = host.ports.iter()
                .filter(|p| p.state == PortState::Open)
                .collect();
                
            if !open_ports.is_empty() {
                host.os_details = detect_os(&target_ip, &host.ports).await;
            }
        }
        
        // CVE Scanning if enabled
        if let Some(ref cve_database) = cve_db {
            if let Err(e) = scan_for_cve(&mut host, cve_database).await {
                eprintln!("⚠️ CVE scan failed for {}: {}", target_ip, e);
            }
        }
        
        // Add host only if it has open ports or if it's the only target
        if !host.ports.iter().any(|p| p.state == PortState::Open) {
            host.status = HostStatus::Down;
        }
        all_hosts.push(host);
    }
    
    pb.finish_with_message("✅ Scan completed!");
    
    // Final Report Generation
    let duration = chrono::Utc::now().signed_duration_since(start_time);
    let mut command = if args.udp_scan {
        format!("nextmap --target {} --ports {} --udp-ports {} -U", args.target, args.ports, args.udp_ports)
    } else {
        format!("nextmap --target {} --ports {}", args.target, args.ports)
    };
    
    if let Some(stealth_mode) = &args.stealth_mode {
        command.push_str(&format!(" --stealth-mode {}", stealth_mode));
    }
    
    if args.cve_scan {
        command.push_str(" --cve-scan");
    }
    
    let scan_results = ScanResult {
        timestamp: start_time.to_rfc3339(),
        command,
        duration_ms: duration.num_milliseconds() as u64,
        hosts: all_hosts,
    };

    // Serialization (Human, JSON, YAML, XML, CSV, MD)
    let output = match args.output_format.as_str() {
        "json" => serde_json::to_string_pretty(&scan_results)?,
        "yaml" => serde_yaml::to_string(&scan_results)?,
        "xml" => generate_xml_output(&scan_results),
        "csv" => generate_csv_output(&scan_results),
        "md" | "markdown" => generate_markdown_output(&scan_results),
        "human" | _ => generate_human_output(&scan_results),
    };
    
    // Output to file or stdout
    if let Some(filename) = args.output_file {
        std::fs::write(&filename, &output)?;
        println!("💾 Results saved to: {}", filename.green());
    } else {
        println!("\n{}", format!("📊 NextMap Scan Report (Format: {})", args.output_format.to_uppercase()).cyan().bold());
        println!("{}", output);
    }

    Ok(())
}