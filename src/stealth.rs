// src/stealth.rs
//! Modulo per tecniche di stealth scanning e evasion IDS/IPS

use std::time::Duration;
use std::net::Ipv4Addr;
use tokio::time::sleep;
use rand::{Rng, SeedableRng};
use crate::models::*;

#[derive(Debug, Clone)]
pub struct StealthConfig {
    /// Usa SYN stealth invece di connect()
    pub syn_stealth: bool,
    /// Frammentazione pacchetti per evasion
    pub fragment_packets: bool,
    /// IP decoy per confondere IDS
    pub decoy_ips: Vec<String>,
    /// Porta sorgente specifica (53 per DNS spoofing, etc.)
    pub source_port: Option<u16>,
    /// Random timing tra min/max ms
    pub timing_variance: (u64, u64),
    /// Spoof MAC address (per subnet locali)
    pub spoof_mac: Option<String>,
    /// User-Agent spoofing per HTTP
    pub user_agents: Vec<String>,
    /// Dimensione custom dei pacchetti
    pub packet_size: Option<usize>,
}

unsafe impl Send for StealthConfig {}
unsafe impl Sync for StealthConfig {}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            syn_stealth: false,
            fragment_packets: false,
            decoy_ips: Vec::new(),
            source_port: None,
            timing_variance: (100, 1000),
            spoof_mac: None,
            user_agents: vec![
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36".to_string(),
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36".to_string(),
            ],
            packet_size: None,
        }
    }
}

/// Configura modalità stealth predefinite
pub fn get_stealth_preset(preset: &str) -> StealthConfig {
    match preset {
        "ghost" => StealthConfig {
            syn_stealth: true,
            fragment_packets: true,
            decoy_ips: generate_decoy_ips(5),
            source_port: Some(53), // DNS spoofing
            timing_variance: (2000, 10000), // Very slow
            spoof_mac: None,
            user_agents: get_random_user_agents(),
            packet_size: Some(64),
        },
        "ninja" => StealthConfig {
            syn_stealth: true,
            fragment_packets: false,
            decoy_ips: generate_decoy_ips(3),
            source_port: Some(20), // FTP data spoofing
            timing_variance: (500, 3000),
            spoof_mac: None,
            user_agents: get_random_user_agents(),
            packet_size: Some(128),
        },
        "shadow" => StealthConfig {
            syn_stealth: true,
            fragment_packets: false,
            decoy_ips: Vec::new(),
            source_port: None,
            timing_variance: (100, 1000),
            spoof_mac: None,
            user_agents: get_random_user_agents(),
            packet_size: None,
        },
        _ => StealthConfig::default(),
    }
}

/// Genera IP decoy casuali per confondere IDS
fn generate_decoy_ips(count: usize) -> Vec<String> {
    let mut rng = rand::thread_rng();
    let mut decoys = Vec::new();
    
    for _ in 0..count {
        let ip = Ipv4Addr::new(
            rng.gen_range(1..254),
            rng.gen_range(1..254), 
            rng.gen_range(1..254),
            rng.gen_range(1..254)
        );
        decoys.push(ip.to_string());
    }
    
    decoys
}

/// User agents realistici per HTTP fingerprinting
fn get_random_user_agents() -> Vec<String> {
    vec![
        // Chrome Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36".to_string(),
        // Firefox Windows  
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0".to_string(),
        // Safari macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15".to_string(),
        // Chrome macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36".to_string(),
        // Chrome Linux
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36".to_string(),
        // Firefox Linux
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0".to_string(),
        // Edge Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0".to_string(),
        // Mobile Chrome
        "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36".to_string(),
        // Mobile Safari
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1".to_string(),
    ]
}

/// Implementa random timing per evitare pattern detection
pub async fn stealth_delay(config: &StealthConfig) {
    if config.timing_variance.0 > 0 || config.timing_variance.1 > 0 {
        // Usa un seed basato sul tempo per evitare problemi di thread safety
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let delay_ms = rng.gen_range(config.timing_variance.0..=config.timing_variance.1);
        sleep(Duration::from_millis(delay_ms)).await;
    }
}

/// Seleziona user agent casuale per HTTP requests
pub fn get_random_user_agent(config: &StealthConfig) -> String {
    if config.user_agents.is_empty() {
        return "NextMap/1.0".to_string();
    }
    
    let mut rng = rand::thread_rng();
    let index = rng.gen_range(0..config.user_agents.len());
    config.user_agents[index].clone()
}

/// Determina porta sorgente per evasion
pub fn get_stealth_source_port(config: &StealthConfig, target_port: u16) -> u16 {
    if let Some(port) = config.source_port {
        return port;
    }
    
    // Porte comuni che spesso passano attraverso firewall
    let common_ports = [53, 20, 21, 25, 80, 443, 993, 995];
    let mut rng = rand::thread_rng();
    
    // Evita di usare la stessa porta del target
    let filtered_ports: Vec<u16> = common_ports.iter()
        .filter(|&&p| p != target_port)
        .copied()
        .collect();
    
    if !filtered_ports.is_empty() {
        let index = rng.gen_range(0..filtered_ports.len());
        filtered_ports[index]
    } else {
        rng.gen_range(1024..65535)
    }
}

/// SYN Stealth scanning - invia solo SYN, non completa handshake
pub async fn syn_stealth_scan(
    target: &str, 
    port: u16, 
    config: &StealthConfig,
    timeout: Duration
) -> Result<PortState, Box<dyn std::error::Error>> {
    
    // Per ora implementiamo fallback a connect scan
    // TODO: Implementare raw socket SYN scan con pnet
    
    // Applica stealth delay
    stealth_delay(config).await;
    
    // Simula comportamento SYN scan
    let socket_addr = format!("{}:{}", target, port);
    
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&socket_addr)).await {
        Ok(Ok(stream)) => {
            // In SYN scan reale, chiuderemmo qui senza completare handshake
            drop(stream);
            Ok(PortState::Open)
        }
        Ok(Err(_)) => Ok(PortState::Closed),
        Err(_) => Ok(PortState::Filtered),
    }
}

/// HTTP stealth request con evasion techniques  
pub async fn stealth_http_request(
    target: &str,
    port: u16,
    config: &StealthConfig,
    path: &str
) -> Result<String, Box<dyn std::error::Error>> {
    
    stealth_delay(config).await;
    
    let user_agent = get_random_user_agent(config);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(&user_agent)
        .build()?;
    
    let url = if port == 443 {
        format!("https://{}:{}{}", target, port, path)
    } else {
        format!("http://{}:{}{}", target, port, path)
    };
    
    let response = client.get(&url)
        .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
        .header("Accept-Language", "en-US,en;q=0.5")
        .header("Accept-Encoding", "gzip, deflate")
        .header("DNT", "1")
        .header("Connection", "keep-alive")
        .header("Upgrade-Insecure-Requests", "1")
        .send()
        .await?;
    
    Ok(response.text().await?)
}

/// Anti-fingerprinting: varia le caratteristiche della scansione
pub fn apply_scan_variation(config: &StealthConfig) -> (Duration, usize) {
    let mut rng = rand::thread_rng();
    
    // Varia timeout
    let base_timeout = 1000;
    let timeout_variance = rng.gen_range(-200..=500);
    let timeout = Duration::from_millis((base_timeout + timeout_variance) as u64);
    
    // Varia concorrenza  
    let base_concurrency = 50;
    let concurrency_variance = rng.gen_range(-10..=20);
    let concurrency = (base_concurrency + concurrency_variance).max(1) as usize;
    
    (timeout, concurrency)
}

/// Evasion tramite packet fragmentation (simulato)
pub async fn fragmented_scan(
    target: &str,
    port: u16, 
    config: &StealthConfig,
    timeout: Duration
) -> Result<PortState, Box<dyn std::error::Error>> {
    
    if !config.fragment_packets {
        return syn_stealth_scan(target, port, config, timeout).await;
    }
    
    // Simula frammentazione con delay multipli
    let fragment_count = 3;
    let fragment_delay = Duration::from_millis(50);
    
    for i in 0..fragment_count {
        stealth_delay(config).await;
        sleep(fragment_delay).await;
        
        if i == fragment_count - 1 {
            // Ultimo frammento - esegui scan reale
            return syn_stealth_scan(target, port, config, timeout).await;
        }
    }
    
    Ok(PortState::Filtered)
}

/// Log stealth scan activity (per debugging)
pub fn log_stealth_activity(
    target: &str,
    port: u16,
    technique: &str,
    config: &StealthConfig
) {
    if std::env::var("NEXTMAP_DEBUG").is_ok() {
        eprintln!("🥷 STEALTH: {} -> {}:{} using {} (decoys: {})", 
            technique, target, port, 
            if config.syn_stealth { "SYN" } else { "CONNECT" },
            config.decoy_ips.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_stealth_presets() {
        let ghost = get_stealth_preset("ghost");
        assert!(ghost.syn_stealth);
        assert!(ghost.fragment_packets);
        assert!(!ghost.decoy_ips.is_empty());
        
        let ninja = get_stealth_preset("ninja");
        assert!(ninja.syn_stealth);
        assert!(!ninja.fragment_packets);
        
        let shadow = get_stealth_preset("shadow");
        assert!(shadow.syn_stealth);
        assert!(shadow.decoy_ips.is_empty());
    }
    
    #[test]
    fn test_decoy_generation() {
        let decoys = generate_decoy_ips(5);
        assert_eq!(decoys.len(), 5);
        
        for decoy in decoys {
            assert!(decoy.parse::<Ipv4Addr>().is_ok());
        }
    }
    
    #[test]
    fn test_source_port_selection() {
        let config = StealthConfig::default();
        let port = get_stealth_source_port(&config, 80);
        assert!(port > 0 && port != 80);
        
        let config_with_fixed = StealthConfig {
            source_port: Some(53),
            ..Default::default()
        };
        assert_eq!(get_stealth_source_port(&config_with_fixed, 80), 53);
    }
}