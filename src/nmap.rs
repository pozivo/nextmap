// src/nmap.rs - Nmap Integration Module for Enhanced Service Detection
// Part of NextMap v0.4.1

use std::process::Command;
use std::path::Path;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Nmap integration for accurate service and version detection
#[derive(Debug, Clone)]
pub struct NmapIntegration {
    /// Path to nmap binary
    pub nmap_path: String,
    /// Enable aggressive service detection
    pub aggressive: bool,
    /// Enable OS detection
    pub os_detection: bool,
    /// Version intensity (0-9, default 7)
    pub version_intensity: u8,
}

impl Default for NmapIntegration {
    fn default() -> Self {
        Self {
            nmap_path: "nmap".to_string(),
            aggressive: false,
            os_detection: false,
            version_intensity: 7,
        }
    }
}

impl NmapIntegration {
    /// Create new Nmap integration instance
    pub fn new(nmap_path: Option<String>) -> Self {
        Self {
            nmap_path: nmap_path.unwrap_or_else(|| "nmap".to_string()),
            ..Default::default()
        }
    }

    /// Check if Nmap is installed and accessible
    pub fn check_nmap_installation(&self) -> Result<String, String> {
        // Try to run nmap --version
        match Command::new(&self.nmap_path)
            .arg("--version")
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    let version_output = String::from_utf8_lossy(&output.stdout);
                    
                    // Extract version number from output
                    // Example: "Nmap version 7.94 ( https://nmap.org )"
                    if let Some(line) = version_output.lines().next() {
                        if line.contains("Nmap version") {
                            let version = line
                                .split("Nmap version")
                                .nth(1)
                                .and_then(|s| s.trim().split_whitespace().next())
                                .unwrap_or("Unknown");
                            return Ok(version.to_string());
                        }
                    }
                    
                    Ok("Unknown version".to_string())
                } else {
                    Err(format!("Nmap execution failed: {:?}", output.status))
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Err("Nmap binary not found. Install from: https://nmap.org/download.html".to_string())
                } else {
                    Err(format!("Failed to execute Nmap: {}", e))
                }
            }
        }
    }

    /// Scan target with Nmap for service detection
    pub fn scan_services(
        &self,
        target: &str,
        ports: &[u16],
    ) -> Result<Vec<NmapServiceResult>, String> {
        // Build port list string
        let port_list = ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");

        // Build nmap command
        let mut cmd = Command::new(&self.nmap_path);
        cmd.arg("-sV"); // Service version detection
        cmd.arg("-p").arg(&port_list);
        cmd.arg("--version-intensity").arg(self.version_intensity.to_string());
        
        if self.aggressive {
            cmd.arg("-A"); // Aggressive scan
        }
        
        if self.os_detection {
            cmd.arg("-O"); // OS detection
        }

        // Output in XML format for easier parsing
        cmd.arg("-oX").arg("-"); // Output XML to stdout
        cmd.arg(target);

        // Execute nmap
        match cmd.output() {
            Ok(output) => {
                if output.status.success() {
                    let xml_output = String::from_utf8_lossy(&output.stdout);
                    self.parse_nmap_xml(&xml_output)
                } else {
                    let error_msg = String::from_utf8_lossy(&output.stderr);
                    Err(format!("Nmap scan failed: {}", error_msg))
                }
            }
            Err(e) => Err(format!("Failed to execute Nmap: {}", e)),
        }
    }

    /// Parse Nmap XML output
    fn parse_nmap_xml(&self, xml: &str) -> Result<Vec<NmapServiceResult>, String> {
        let mut results = Vec::new();

        // Simple XML parsing (in production, use a proper XML parser like quick-xml)
        // For now, use regex-like approach for key fields
        
        // Extract ports and services
        for line in xml.lines() {
            if line.contains("<port protocol=") {
                // Parse port info
                if let Some(result) = self.parse_port_element(line, xml) {
                    results.push(result);
                }
            }
        }

        Ok(results)
    }

    /// Parse individual port element from XML
    fn parse_port_element(&self, port_line: &str, full_xml: &str) -> Option<NmapServiceResult> {
        // Extract port number
        let port_num = port_line
            .split("portid=\"")
            .nth(1)?
            .split('"')
            .next()?
            .parse::<u16>()
            .ok()?;

        // Extract protocol
        let protocol = port_line
            .split("protocol=\"")
            .nth(1)?
            .split('"')
            .next()?
            .to_string();

        // Look for state
        let state = if full_xml.contains(&format!("portid=\"{}\"", port_num)) {
            if full_xml.contains("state=\"open\"") {
                "open".to_string()
            } else if full_xml.contains("state=\"closed\"") {
                "closed".to_string()
            } else {
                "filtered".to_string()
            }
        } else {
            "unknown".to_string()
        };

        // Extract service name and version
        let (service_name, service_version, service_product) = 
            self.extract_service_info(port_num, full_xml);

        Some(NmapServiceResult {
            port: port_num,
            protocol,
            state,
            service_name,
            service_version,
            service_product,
            os_info: None,
        })
    }

    /// Extract service information from XML
    fn extract_service_info(&self, port: u16, xml: &str) -> (Option<String>, Option<String>, Option<String>) {
        let mut service_name = None;
        let mut service_version = None;
        let mut service_product = None;

        // Find service element for this port
        for line in xml.lines() {
            if line.contains(&format!("portid=\"{}\"", port)) {
                // Look for service element in nearby lines
                let port_section: Vec<&str> = xml
                    .lines()
                    .skip_while(|l| !l.contains(&format!("portid=\"{}\"", port)))
                    .take(10)
                    .collect();

                for service_line in port_section {
                    if service_line.contains("<service ") {
                        // Extract name
                        if let Some(name) = service_line.split("name=\"").nth(1) {
                            service_name = Some(name.split('"').next().unwrap_or("").to_string());
                        }
                        
                        // Extract product
                        if let Some(product) = service_line.split("product=\"").nth(1) {
                            service_product = Some(product.split('"').next().unwrap_or("").to_string());
                        }
                        
                        // Extract version
                        if let Some(version) = service_line.split("version=\"").nth(1) {
                            service_version = Some(version.split('"').next().unwrap_or("").to_string());
                        }
                        
                        break;
                    }
                }
                break;
            }
        }

        (service_name, service_version, service_product)
    }

    /// Get Nmap version
    pub fn get_version(&self) -> Option<String> {
        self.check_nmap_installation().ok()
    }
}

/// Nmap service detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapServiceResult {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service_name: Option<String>,
    pub service_version: Option<String>,
    pub service_product: Option<String>,
    pub os_info: Option<String>,
}

impl NmapServiceResult {
    /// Format service version string
    pub fn formatted_version(&self) -> String {
        let mut parts = Vec::new();
        
        if let Some(ref product) = self.service_product {
            parts.push(product.clone());
        }
        
        if let Some(ref version) = self.service_version {
            parts.push(version.clone());
        }
        
        if parts.is_empty() {
            "Unknown".to_string()
        } else {
            parts.join(" ")
        }
    }

    /// Get service name or default
    pub fn service_or_unknown(&self) -> String {
        self.service_name.clone().unwrap_or_else(|| "unknown".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nmap_integration_creation() {
        let nmap = NmapIntegration::new(None);
        assert_eq!(nmap.nmap_path, "nmap");
        assert_eq!(nmap.version_intensity, 7);
        assert!(!nmap.aggressive);
    }

    #[test]
    fn test_custom_nmap_path() {
        let nmap = NmapIntegration::new(Some("/usr/local/bin/nmap".to_string()));
        assert_eq!(nmap.nmap_path, "/usr/local/bin/nmap");
    }

    #[test]
    fn test_nmap_result_formatting() {
        let result = NmapServiceResult {
            port: 80,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            service_name: Some("http".to_string()),
            service_version: Some("2.4.41".to_string()),
            service_product: Some("Apache httpd".to_string()),
            os_info: None,
        };

        assert_eq!(result.formatted_version(), "Apache httpd 2.4.41");
        assert_eq!(result.service_or_unknown(), "http");
    }

    #[test]
    fn test_nmap_result_unknown() {
        let result = NmapServiceResult {
            port: 12345,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            service_name: None,
            service_version: None,
            service_product: None,
            os_info: None,
        };

        assert_eq!(result.formatted_version(), "Unknown");
        assert_eq!(result.service_or_unknown(), "unknown");
    }
}
