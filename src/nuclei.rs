// src/nuclei.rs
//! Nuclei Integration Module - Active Vulnerability Scanning
//! 
//! This module integrates ProjectDiscovery's Nuclei scanner for active
//! vulnerability detection with 6,000+ CVE templates.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use std::path::PathBuf;
use crate::models::*;

/// Nuclei scanner integration
#[derive(Debug, Clone)]
pub struct NucleiIntegration {
    /// Path to nuclei binary
    pub nuclei_path: String,
    /// Path to nuclei templates directory
    pub templates_dir: Option<String>,
    /// Severity filter (critical, high, medium, low, info)
    pub severity_filter: Vec<String>,
    /// Tags filter (e.g., cve, rce, sqli, xss)
    pub tags_filter: Vec<String>,
    /// Rate limit (requests per second)
    pub rate_limit: usize,
    /// Timeout per template (seconds)
    pub timeout: u32,
    /// Number of concurrent templates
    pub concurrency: usize,
    /// Enable verbose output
    pub verbose: bool,
}

impl NucleiIntegration {
    /// Create new Nuclei integration with default settings
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let nuclei_path = Self::detect_nuclei_binary()?;
        
        Ok(NucleiIntegration {
            nuclei_path,
            templates_dir: None,
            severity_filter: vec!["critical".to_string(), "high".to_string()],
            tags_filter: vec![],
            rate_limit: 150,
            timeout: 10,
            concurrency: 25,
            verbose: false,
        })
    }
    
    /// Create new Nuclei integration with custom settings
    pub fn with_config(
        nuclei_path: Option<String>,
        severity: Vec<String>,
        tags: Vec<String>,
        rate_limit: usize,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let path = match nuclei_path {
            Some(p) => p,
            None => Self::detect_nuclei_binary()?,
        };
        
        Ok(NucleiIntegration {
            nuclei_path: path,
            templates_dir: None,
            severity_filter: severity,
            tags_filter: tags,
            rate_limit,
            timeout: 10,
            concurrency: 25,
            verbose: false,
        })
    }
    
    /// Auto-detect nuclei binary location
    fn detect_nuclei_binary() -> Result<String, Box<dyn std::error::Error>> {
        // Try common locations
        let candidates = vec![
            "nuclei",                          // In PATH
            "nuclei.exe",                      // Windows in PATH
            "./nuclei",                        // Current directory
            "./nuclei.exe",                    // Current directory (Windows)
            "/usr/local/bin/nuclei",           // Linux/Mac
            "/usr/bin/nuclei",                 // Linux
            "C:\\ProgramData\\nuclei\\nuclei.exe",  // Windows Program Data
        ];
        
        for candidate in candidates {
            if let Ok(output) = Command::new(candidate).arg("-version").output() {
                if output.status.success() {
                    println!("✅ Found Nuclei: {}", candidate);
                    return Ok(candidate.to_string());
                }
            }
        }
        
        Err("Nuclei binary not found. Install from: https://github.com/projectdiscovery/nuclei".into())
    }
    
    /// Verify Nuclei installation and get version
    pub fn verify_installation(&self) -> Result<String, Box<dyn std::error::Error>> {
        let output = Command::new(&self.nuclei_path)
            .arg("-version")
            .output()?;
        
        if !output.status.success() {
            return Err("Nuclei binary found but version check failed".into());
        }
        
        let version = String::from_utf8_lossy(&output.stdout);
        let version_line = version.lines()
            .find(|line| line.contains("Nuclei") || line.contains("v"))
            .unwrap_or("Unknown version");
        
        Ok(version_line.to_string())
    }
    
    /// Update Nuclei templates from GitHub
    pub async fn update_templates(&self) -> Result<String, Box<dyn std::error::Error>> {
        println!("🔄 Updating Nuclei templates...");
        
        let output = Command::new(&self.nuclei_path)
            .arg("-update-templates")
            .arg("-silent")
            .output()?;
        
        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Template update failed: {}", error).into());
        }
        
        let result = String::from_utf8_lossy(&output.stdout);
        println!("✅ Templates updated successfully");
        
        Ok(result.to_string())
    }
    
    /// Scan a single target with Nuclei
    pub async fn scan_target(
        &self,
        target: &str,
        port: u16,
        service: Option<&str>,
    ) -> Result<Vec<NucleiVulnerability>, Box<dyn std::error::Error>> {
        // Build target URL
        let protocol = if port == 443 || port == 8443 { "https" } else { "http" };
        let url = if port == 80 || port == 443 {
            format!("{}://{}", protocol, target)
        } else {
            format!("{}://{}:{}", protocol, target, port)
        };
        
        println!("🔍 Running Nuclei scan on {}...", url);
        
        // Build command
        let mut cmd = Command::new(&self.nuclei_path);
        cmd.arg("-target").arg(&url)
           .arg("-json")                    // JSON output
           .arg("-silent")                  // No banner/progress
           .arg("-no-color")                // Clean output
           .arg("-rate-limit").arg(self.rate_limit.to_string())
           .arg("-timeout").arg(self.timeout.to_string())
           .arg("-bulk-size").arg(self.concurrency.to_string());
        
        // Add severity filter
        if !self.severity_filter.is_empty() {
            let severities = self.severity_filter.join(",");
            cmd.arg("-severity").arg(severities);
        }
        
        // Add tags filter (service-specific + global)
        let mut all_tags = self.tags_filter.clone();
        if let Some(svc) = service {
            // Map service names to Nuclei tags
            let service_tags = match svc.to_lowercase().as_str() {
                "apache" | "apache2" | "httpd" => vec!["apache"],
                "nginx" => vec!["nginx"],
                "iis" | "microsoft-iis" => vec!["iis", "microsoft"],
                "wordpress" => vec!["wordpress", "wp"],
                "drupal" => vec!["drupal"],
                "joomla" => vec!["joomla"],
                "jenkins" => vec!["jenkins"],
                "gitlab" => vec!["gitlab"],
                "tomcat" => vec!["tomcat"],
                "weblogic" => vec!["weblogic", "oracle"],
                "php" => vec!["php"],
                "laravel" => vec!["laravel"],
                "django" => vec!["django"],
                "spring" | "spring boot" => vec!["spring"],
                _ => vec![],
            };
            
            for tag in service_tags {
                if !all_tags.contains(&tag.to_string()) {
                    all_tags.push(tag.to_string());
                }
            }
        }
        
        if !all_tags.is_empty() {
            let tags_str = all_tags.join(",");
            cmd.arg("-tags").arg(tags_str);
        }
        
        // Add templates directory if specified
        if let Some(ref templates) = self.templates_dir {
            cmd.arg("-t").arg(templates);
        }
        
        // Execute scan
        let output = cmd.output()?;
        
        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            if !error.is_empty() {
                eprintln!("⚠️  Nuclei warning: {}", error);
            }
        }
        
        // Parse JSON output
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut vulnerabilities = Vec::new();
        
        for line in stdout.lines() {
            if line.trim().is_empty() {
                continue;
            }
            
            match serde_json::from_str::<NucleiVulnerability>(line) {
                Ok(vuln) => vulnerabilities.push(vuln),
                Err(e) => {
                    if self.verbose {
                        eprintln!("⚠️  Failed to parse Nuclei output: {}", e);
                        eprintln!("   Line: {}", line);
                    }
                }
            }
        }
        
        println!("✅ Nuclei scan complete: {} vulnerabilities found", vulnerabilities.len());
        
        Ok(vulnerabilities)
    }
    
    /// Scan multiple targets in parallel
    pub async fn scan_targets_bulk(
        &self,
        targets: &[(String, u16, Option<String>)],
    ) -> Result<HashMap<String, Vec<NucleiVulnerability>>, Box<dyn std::error::Error>> {
        let mut results = HashMap::new();
        
        for (target, port, service) in targets {
            let key = format!("{}:{}", target, port);
            match self.scan_target(target, *port, service.as_deref()).await {
                Ok(vulns) => {
                    results.insert(key, vulns);
                }
                Err(e) => {
                    eprintln!("⚠️  Failed to scan {}: {}", key, e);
                }
            }
        }
        
        Ok(results)
    }
    
    /// Convert Nuclei vulnerability to NextMap Vulnerability format
    pub fn to_nextmap_vulnerability(
        &self,
        nuclei_vuln: &NucleiVulnerability,
        _service: Option<String>,
        _version: Option<String>,
        port: u16,
    ) -> Vulnerability {
        // Extract CVE ID from template or use template ID
        let cve_id = nuclei_vuln.extract_cve_id()
            .unwrap_or_else(|| nuclei_vuln.template_id.clone());
        
        // Map Nuclei severity to NextMap severity string
        let severity = nuclei_vuln.info.severity.to_uppercase();
        
        // Build description
        let description = if let Some(desc) = &nuclei_vuln.info.description {
            desc.clone()
        } else {
            format!("Nuclei template: {} - {}", nuclei_vuln.template_id, nuclei_vuln.info.name)
        };
        
        Vulnerability {
            cve_id,
            severity,
            description_short: description,
            service_port: port,
        }
    }
}

impl Default for NucleiIntegration {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| {
            NucleiIntegration {
                nuclei_path: "nuclei".to_string(),
                templates_dir: None,
                severity_filter: vec!["critical".to_string(), "high".to_string()],
                tags_filter: vec![],
                rate_limit: 150,
                timeout: 10,
                concurrency: 25,
                verbose: false,
            }
        })
    }
}

/// Nuclei vulnerability result (JSON output format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NucleiVulnerability {
    #[serde(rename = "template-id")]
    pub template_id: String,
    
    #[serde(rename = "template-path")]
    pub template_path: Option<String>,
    
    pub info: NucleiInfo,
    
    #[serde(rename = "matcher-name")]
    pub matcher_name: Option<String>,
    
    #[serde(rename = "matched-at")]
    pub matched_at: String,
    
    #[serde(rename = "extracted-results")]
    pub extracted_results: Option<Vec<String>>,
    
    pub timestamp: Option<String>,
    
    #[serde(rename = "curl-command")]
    pub curl_command: Option<String>,
}

impl NucleiVulnerability {
    /// Extract CVE ID from template ID or classification
    pub fn extract_cve_id(&self) -> Option<String> {
        // Check classification first
        if let Some(cve) = self.info.classification.get("cve-id") {
            return Some(cve.clone());
        }
        
        // Check template ID (e.g., "CVE-2024-38476" or "cves/2024/CVE-2024-38476")
        let template = &self.template_id;
        if template.starts_with("CVE-") {
            return Some(template.clone());
        }
        
        // Extract from path-like template ID
        if let Some(cve_part) = template.split('/').find(|part| part.starts_with("CVE-")) {
            return Some(cve_part.to_string());
        }
        
        None
    }
}

/// Nuclei template info structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NucleiInfo {
    pub name: String,
    
    pub author: Option<Vec<String>>,
    
    pub severity: String,
    
    pub description: Option<String>,
    
    pub reference: Option<Vec<String>>,
    
    pub tags: Option<Vec<String>>,
    
    pub classification: HashMap<String, String>,
    
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// Nuclei scan statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NucleiStats {
    pub total_templates: usize,
    pub matched_templates: usize,
    pub total_requests: usize,
    pub duration: f64,
    pub vulnerabilities_by_severity: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_nuclei_detection() {
        match NucleiIntegration::detect_nuclei_binary() {
            Ok(path) => println!("Nuclei found at: {}", path),
            Err(e) => println!("Nuclei not found (expected in CI): {}", e),
        }
    }
    
    #[test]
    fn test_cve_extraction() {
        let vuln = NucleiVulnerability {
            template_id: "CVE-2024-38476".to_string(),
            template_path: None,
            info: NucleiInfo {
                name: "Apache Path Traversal".to_string(),
                author: None,
                severity: "critical".to_string(),
                description: None,
                reference: None,
                tags: None,
                classification: HashMap::new(),
                metadata: None,
            },
            matcher_name: None,
            matched_at: "http://example.com".to_string(),
            extracted_results: None,
            timestamp: None,
            curl_command: None,
        };
        
        assert_eq!(vuln.extract_cve_id(), Some("CVE-2024-38476".to_string()));
    }
    
    #[test]
    fn test_cve_extraction_from_path() {
        let vuln = NucleiVulnerability {
            template_id: "cves/2024/CVE-2024-38476".to_string(),
            template_path: None,
            info: NucleiInfo {
                name: "Apache Path Traversal".to_string(),
                author: None,
                severity: "critical".to_string(),
                description: None,
                reference: None,
                tags: None,
                classification: HashMap::new(),
                metadata: None,
            },
            matcher_name: None,
            matched_at: "http://example.com".to_string(),
            extracted_results: None,
            timestamp: None,
            curl_command: None,
        };
        
        assert_eq!(vuln.extract_cve_id(), Some("CVE-2024-38476".to_string()));
    }
    
    #[test]
    fn test_severity_mapping() {
        let integration = NucleiIntegration::default();
        
        let vuln = NucleiVulnerability {
            template_id: "test".to_string(),
            template_path: None,
            info: NucleiInfo {
                name: "Test".to_string(),
                author: None,
                severity: "critical".to_string(),
                description: None,
                reference: None,
                tags: None,
                classification: HashMap::new(),
                metadata: None,
            },
            matcher_name: None,
            matched_at: "http://example.com".to_string(),
            extracted_results: None,
            timestamp: None,
            curl_command: None,
        };
        
        let nm_vuln = integration.to_nextmap_vulnerability(&vuln, None, None, 80);
        assert_eq!(nm_vuln.severity, "CRITICAL");
    }
}
