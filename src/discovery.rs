// src/discovery.rs
// Network Discovery Module - ARP Scan, Ping Sweep, Neighbor Discovery

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::time::timeout;
use pnet::datalink;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::icmp::{echo_request, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use serde::{Deserialize, Serialize};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredHost {
    pub ip_address: IpAddr,
    pub mac_address: Option<String>, // Serialize MAC as string
    pub hostname: Option<String>,
    pub response_time: Option<u64>, // in milliseconds
    pub discovery_method: String,
    pub vendor: Option<String>,
    pub is_gateway: bool,
    pub ports_hint: Vec<u16>, // Commonly open ports discovered
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterfaceInfo {
    pub name: String,
    pub ip_address: IpAddr,
    pub netmask: Option<IpAddr>,
    pub mac_address: Option<String>, // Serialize MAC as string
    pub is_up: bool,
    pub is_loopback: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDiscoveryResult {
    pub discovered_hosts: Vec<DiscoveredHost>,
    pub network_interfaces: Vec<NetworkInterfaceInfo>,
    pub network_ranges: Vec<String>,
    pub gateway: Option<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
    pub scan_duration: u64,
    pub discovery_methods_used: Vec<String>,
}

pub struct NetworkDiscovery {
    pub timeout: Duration,
    pub max_concurrent: usize,
    pub include_loopback: bool,
    pub aggressive_mode: bool,
}

impl Default for NetworkDiscovery {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(1000),
            max_concurrent: 50,
            include_loopback: false,
            aggressive_mode: false,
        }
    }
}

impl NetworkDiscovery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_concurrency(mut self, max_concurrent: usize) -> Self {
        self.max_concurrent = max_concurrent;
        self
    }

    pub fn aggressive(mut self) -> Self {
        self.aggressive_mode = true;
        self.timeout = Duration::from_millis(500);
        self.max_concurrent = 100;
        self
    }

    // Main discovery function
    pub async fn discover_network(&self) -> Result<NetworkDiscoveryResult, Box<dyn std::error::Error>> {
        let start_time = Instant::now();
        let mut discovered_hosts = Vec::new();
        let mut discovery_methods = Vec::new();

        println!("{}", "🔍 Starting Network Discovery...".green().bold());

        // 1. Get network interfaces
        let interfaces = self.get_network_interfaces()?;
        println!("📡 Found {} network interfaces", interfaces.len().to_string().cyan());

        // 2. Determine network ranges to scan
        let network_ranges = self.get_network_ranges(&interfaces);
        println!("🌐 Scanning {} network ranges", network_ranges.len().to_string().cyan());

        // 3. Get gateway and DNS information
        let gateway = self.get_default_gateway().await;
        let dns_servers = self.get_dns_servers().await;

        // 4. Perform ARP scan for local networks
        if self.can_perform_arp_scan() {
            println!("{}", "🔗 Performing ARP scan...".yellow());
            let arp_hosts = self.arp_scan(&interfaces).await?;
            discovered_hosts.extend(arp_hosts);
            discovery_methods.push("ARP Scan".to_string());
        }

        // 5. Perform ping sweep
        println!("{}", "📡 Performing ping sweep...".yellow());
        let ping_hosts = self.ping_sweep(&network_ranges).await?;
        discovered_hosts.extend(ping_hosts);
        discovery_methods.push("ICMP Ping Sweep".to_string());

        // 6. Perform neighbor discovery (IPv6)
        if self.aggressive_mode {
            println!("{}", "🔍 Performing neighbor discovery...".yellow());
            let neighbor_hosts = self.neighbor_discovery(&interfaces).await?;
            discovered_hosts.extend(neighbor_hosts);
            discovery_methods.push("IPv6 Neighbor Discovery".to_string());
        }

        // 7. Reverse DNS lookup for discovered hosts
        println!("{}", "🏷️  Performing reverse DNS lookups...".yellow());
        self.resolve_hostnames(&mut discovered_hosts).await;

        // 8. Deduplicate hosts
        discovered_hosts = self.deduplicate_hosts(discovered_hosts);

        // 9. Mark gateway
        if let Some(gw_ip) = gateway {
            for host in &mut discovered_hosts {
                if host.ip_address == gw_ip {
                    host.is_gateway = true;
                    break;
                }
            }
        }

        let scan_duration = start_time.elapsed().as_millis() as u64;

        Ok(NetworkDiscoveryResult {
            discovered_hosts,
            network_interfaces: interfaces,
            network_ranges,
            gateway,
            dns_servers,
            scan_duration,
            discovery_methods_used: discovery_methods,
        })
    }

    // Get available network interfaces
    fn get_network_interfaces(&self) -> Result<Vec<NetworkInterfaceInfo>, Box<dyn std::error::Error>> {
        let mut interfaces = Vec::new();

        for iface in datalink::interfaces() {
            if !self.include_loopback && iface.is_loopback() {
                continue;
            }

            for ip_network in &iface.ips {
                let interface = NetworkInterfaceInfo {
                    name: iface.name.clone(),
                    ip_address: ip_network.ip(),
                    netmask: Some(ip_network.mask()),
                    mac_address: iface.mac.map(|m| m.to_string()),
                    is_up: iface.is_up(),
                    is_loopback: iface.is_loopback(),
                };
                interfaces.push(interface);
            }
        }

        Ok(interfaces)
    }

    // Determine network ranges to scan
    fn get_network_ranges(&self, interfaces: &[NetworkInterfaceInfo]) -> Vec<String> {
        let mut ranges = Vec::new();

        for interface in interfaces {
            if interface.is_loopback && !self.include_loopback {
                continue;
            }

            match (interface.ip_address, interface.netmask) {
                (IpAddr::V4(ip), Some(IpAddr::V4(mask))) => {
                    if let Ok(network) = ipnet::Ipv4Net::with_netmask(ip, mask) {
                        ranges.push(network.to_string());
                    }
                }
                (IpAddr::V6(ip), Some(IpAddr::V6(_mask))) => {
                    // IPv6 network calculation would go here
                    ranges.push(format!("{}/64", ip));
                }
                _ => {}
            }
        }

        // Add common private ranges if none found
        if ranges.is_empty() {
            ranges.extend(vec![
                "192.168.1.0/24".to_string(),
                "192.168.0.0/24".to_string(),
                "10.0.0.0/24".to_string(),
            ]);
        }

        ranges
    }

    // Check if ARP scan can be performed (requires privileges)
    fn can_perform_arp_scan(&self) -> bool {
        // On Windows, check if running as admin
        #[cfg(windows)]
        {
            // Simplified privilege check for Windows - assume admin if we can bind to privileged ports
            false
        }

        // On Unix systems, check if running as root
        #[cfg(unix)]
        {
            unsafe { libc::geteuid() == 0 }
        }

        #[cfg(not(any(windows, unix)))]
        false
    }

    // Perform ARP scan for local network discovery
    async fn arp_scan(&self, _interfaces: &[NetworkInterfaceInfo]) -> Result<Vec<DiscoveredHost>, Box<dyn std::error::Error>> {
        let mut discovered = Vec::new();

        // This is a simplified ARP scan - in practice, you'd need raw socket privileges
        // For now, we'll use system ARP table as fallback
        discovered.extend(self.get_system_arp_table().await?);

        Ok(discovered)
    }

    // Get system ARP table
    async fn get_system_arp_table(&self) -> Result<Vec<DiscoveredHost>, Box<dyn std::error::Error>> {
        let mut discovered = Vec::new();

        #[cfg(windows)]
        {
            let output = Command::new("arp")
                .args(&["-a"])
                .output()
                .await?;

            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    if let Some(host) = self.parse_windows_arp_line(line) {
                        discovered.push(host);
                    }
                }
            }
        }

        #[cfg(unix)]
        {
            let output = Command::new("arp")
                .args(&["-a"])
                .output()
                .await?;

            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    if let Some(host) = self.parse_unix_arp_line(line) {
                        discovered.push(host);
                    }
                }
            }
        }

        Ok(discovered)
    }

    #[cfg(windows)]
    fn parse_windows_arp_line(&self, line: &str) -> Option<DiscoveredHost> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                if let Ok(mac) = parts[1].parse::<MacAddr>() {
                    return Some(DiscoveredHost {
                        ip_address: IpAddr::V4(ip),
                        mac_address: Some(mac.to_string()),
                        hostname: None,
                        response_time: None,
                        discovery_method: "ARP Table".to_string(),
                        vendor: None,
                        is_gateway: false,
                        ports_hint: Vec::new(),
                    });
                }
            }
        }
        None
    }

    #[cfg(unix)]
    fn parse_unix_arp_line(&self, line: &str) -> Option<DiscoveredHost> {
        // Parse Unix/Linux arp output format
        if line.contains("(") && line.contains(")") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                // Extract IP from parentheses
                if let Some(ip_start) = line.find('(') {
                    if let Some(ip_end) = line.find(')') {
                        let ip_str = &line[ip_start + 1..ip_end];
                        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                            // Try to parse MAC address
                            for part in &parts {
                                if let Ok(mac) = part.parse::<MacAddr>() {
                                    return Some(DiscoveredHost {
                                        ip_address: IpAddr::V4(ip),
                                        mac_address: Some(mac.to_string()),
                                        hostname: None,
                                        response_time: None,
                                        discovery_method: "ARP Table".to_string(),
                                        vendor: None,
                                        is_gateway: false,
                                        ports_hint: Vec::new(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    // Perform ICMP ping sweep
    async fn ping_sweep(&self, network_ranges: &[String]) -> Result<Vec<DiscoveredHost>, Box<dyn std::error::Error>> {
        let mut discovered = Vec::new();
        // let mut tasks = Vec::new(); // TODO: Fix task handling

        for range in network_ranges {
            if let Ok(network) = range.parse::<ipnet::Ipv4Net>() {
                let hosts: Vec<Ipv4Addr> = network.hosts().collect();
                
                println!("🔍 Pinging {} hosts in range {}", hosts.len().to_string().cyan(), range);
                
                let pb = ProgressBar::new(hosts.len() as u64);
                pb.set_style(ProgressStyle::default_bar()
                    .template("  [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")?
                    .progress_chars("#>-"));

                let pb = std::sync::Arc::new(pb);

                for chunk in hosts.chunks(self.max_concurrent) {
                    let mut chunk_tasks = Vec::new();
                    
                    for &ip in chunk {
                        let pb_clone = pb.clone();
                        let timeout = self.timeout;
                        
                        let task = tokio::spawn(async move {
                            let result = Self::ping_host(IpAddr::V4(ip), timeout).await;
                            pb_clone.inc(1);
                            result
                        });
                        
                        chunk_tasks.push(task);
                    }

                    for task in chunk_tasks {
                        if let Ok(Some(host)) = task.await {
                            discovered.push(host);
                        }
                    }
                }

                pb.finish_with_message("Ping sweep completed");
            }
        }

        Ok(discovered)
    }

    // Ping a single host
    async fn ping_host(ip: IpAddr, timeout_duration: Duration) -> Option<DiscoveredHost> {
        let start = Instant::now();

        #[cfg(windows)]
        let ping_cmd = "ping";
        #[cfg(unix)]
        let ping_cmd = "ping";

        let output = timeout(
            timeout_duration,
            Command::new(ping_cmd)
                .args(&["-n", "1", &ip.to_string()]) // Windows
                .output()
        ).await;

        #[cfg(unix)]
        let output = timeout(
            timeout_duration,
            Command::new(ping_cmd)
                .args(&["-c", "1", "-W", "1", &ip.to_string()]) // Unix/Linux
                .output()
        ).await;

        if let Ok(Ok(output)) = output {
            if output.status.success() {
                let response_time = start.elapsed().as_millis() as u64;
                return Some(DiscoveredHost {
                    ip_address: ip,
                    mac_address: None,
                    hostname: None,
                    response_time: Some(response_time),
                    discovery_method: "ICMP Ping".to_string(),
                    vendor: None,
                    is_gateway: false,
                    ports_hint: Vec::new(),
                });
            }
        }

        None
    }

    // IPv6 Neighbor Discovery
    async fn neighbor_discovery(&self, _interfaces: &[NetworkInterfaceInfo]) -> Result<Vec<DiscoveredHost>, Box<dyn std::error::Error>> {
        let mut discovered = Vec::new();

        // Use system neighbor table for IPv6
        #[cfg(unix)]
        {
            let output = Command::new("ip")
                .args(&["neigh", "show"])
                .output()
                .await?;

            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    if let Some(host) = self.parse_neighbor_line(line) {
                        discovered.push(host);
                    }
                }
            }
        }

        #[cfg(windows)]
        {
            let output = Command::new("netsh")
                .args(&["interface", "ipv6", "show", "neighbors"])
                .output()
                .await?;

            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    if let Some(host) = self.parse_windows_neighbor_line(line) {
                        discovered.push(host);
                    }
                }
            }
        }

        Ok(discovered)
    }

    fn parse_neighbor_line(&self, line: &str) -> Option<DiscoveredHost> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            if let Ok(ip) = parts[0].parse::<IpAddr>() {
                if let Ok(mac) = parts[4].parse::<MacAddr>() {
                    return Some(DiscoveredHost {
                        ip_address: ip,
                        mac_address: Some(mac.to_string()),
                        hostname: None,
                        response_time: None,
                        discovery_method: "IPv6 Neighbor Discovery".to_string(),
                        vendor: None,
                        is_gateway: false,
                        ports_hint: Vec::new(),
                    });
                }
            }
        }
        None
    }

    #[cfg(windows)]
    fn parse_windows_neighbor_line(&self, line: &str) -> Option<DiscoveredHost> {
        // Parse Windows netsh neighbor output
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            if let Ok(ip) = parts[0].parse::<IpAddr>() {
                if let Ok(mac) = parts[1].parse::<MacAddr>() {
                    return Some(DiscoveredHost {
                        ip_address: ip,
                        mac_address: Some(mac.to_string()),
                        hostname: None,
                        response_time: None,
                        discovery_method: "Windows Neighbor Table".to_string(),
                        vendor: None,
                        is_gateway: false,
                        ports_hint: Vec::new(),
                    });
                }
            }
        }
        None
    }

    // Get default gateway
    async fn get_default_gateway(&self) -> Option<IpAddr> {
        #[cfg(windows)]
        {
            if let Ok(output) = Command::new("route")
                .args(&["print", "0.0.0.0"])
                .output()
                .await
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    if line.contains("0.0.0.0") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 3 {
                            if let Ok(gateway) = parts[2].parse::<Ipv4Addr>() {
                                return Some(IpAddr::V4(gateway));
                            }
                        }
                    }
                }
            }
        }

        #[cfg(unix)]
        {
            if let Ok(output) = Command::new("ip")
                .args(&["route", "show", "default"])
                .output()
                .await
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    if line.contains("default via") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 3 {
                            if let Ok(gateway) = parts[2].parse::<IpAddr>() {
                                return Some(gateway);
                            }
                        }
                    }
                }
            }
        }

        None
    }

    // Get DNS servers
    async fn get_dns_servers(&self) -> Vec<IpAddr> {
        let mut dns_servers = Vec::new();

        #[cfg(windows)]
        {
            if let Ok(output) = Command::new("nslookup")
                .args(&["localhost"])
                .output()
                .await
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    if line.contains("Server:") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            if let Ok(dns) = parts[1].parse::<IpAddr>() {
                                dns_servers.push(dns);
                            }
                        }
                    }
                }
            }
        }

        #[cfg(unix)]
        {
            if let Ok(content) = tokio::fs::read_to_string("/etc/resolv.conf").await {
                for line in content.lines() {
                    if line.starts_with("nameserver") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            if let Ok(dns) = parts[1].parse::<IpAddr>() {
                                dns_servers.push(dns);
                            }
                        }
                    }
                }
            }
        }

        dns_servers
    }

    // Resolve hostnames for discovered hosts
    async fn resolve_hostnames(&self, hosts: &mut [DiscoveredHost]) {
        let pb = ProgressBar::new(hosts.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("  [{elapsed_precise}] [{bar:40.green/blue}] {pos}/{len} Resolving hostnames...")
            .unwrap()
            .progress_chars("#>-"));

        for host in hosts.iter_mut() {
            if let Ok(output) = timeout(
                Duration::from_millis(2000),
                Command::new("nslookup")
                    .arg(host.ip_address.to_string())
                    .output()
            ).await {
                if let Ok(output) = output {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    for line in output_str.lines() {
                        if line.contains("name =") {
                            let parts: Vec<&str> = line.split(" = ").collect();
                            if parts.len() >= 2 {
                                let hostname = parts[1].trim_end_matches('.').to_string();
                                host.hostname = Some(hostname);
                                break;
                            }
                        }
                    }
                }
            }
            pb.inc(1);
        }

        pb.finish_with_message("Hostname resolution completed");
    }

    // Remove duplicate hosts
    fn deduplicate_hosts(&self, hosts: Vec<DiscoveredHost>) -> Vec<DiscoveredHost> {
        let mut unique_hosts = HashMap::new();

        for host in hosts {
            unique_hosts.entry(host.ip_address)
                .and_modify(|existing: &mut DiscoveredHost| {
                    // Merge information from multiple discovery methods
                    if host.mac_address.is_some() && existing.mac_address.is_none() {
                        existing.mac_address = host.mac_address.clone();
                    }
                    if host.hostname.is_some() && existing.hostname.is_none() {
                        existing.hostname = host.hostname.clone();
                    }
                    if host.response_time.is_some() && existing.response_time.is_none() {
                        existing.response_time = host.response_time;
                    }
                    if !existing.discovery_method.contains(&host.discovery_method) {
                        existing.discovery_method = format!("{}, {}", existing.discovery_method, host.discovery_method);
                    }
                })
                .or_insert(host);
        }

        unique_hosts.into_values().collect()
    }
}

// Helper function to get MAC address vendor
pub fn get_mac_vendor(mac_str: &str) -> Option<String> {
    // Parse MAC address and extract OUI (first 3 octets)
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    
    let oui = format!("{}:{}:{}", parts[0], parts[1], parts[2]).to_uppercase();
    
    // Basic vendor mapping - in practice, you'd use a proper OUI database
    match oui.as_str() {
        "00:50:56" => Some("VMware".to_string()),
        "08:00:27" => Some("VirtualBox".to_string()),
        "00:0C:29" => Some("VMware".to_string()),
        "00:1B:21" => Some("Intel".to_string()),
        "00:23:24" => Some("Apple".to_string()),
        "28:CF:E9" => Some("Apple".to_string()),
        "AC:DE:48" => Some("Apple".to_string()),
        _ => None,
    }
}