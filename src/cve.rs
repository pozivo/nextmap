// src/cve.rs
//! Modulo per scanning automatico delle vulnerabilità CVE

use std::collections::HashMap;
use rusqlite::{Connection, Result as SqlResult};
use serde::{Deserialize, Serialize};
use reqwest;
use crate::models::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CVEEntry {
    pub cve_id: String,
    pub description: String,
    pub severity: String,
    pub cvss_score: f32,
    pub affected_products: Vec<String>,
    pub affected_versions: Vec<String>,
    pub published_date: String,
    pub modified_date: String,
    pub references: Vec<String>,
    pub exploit_available: bool,
}

#[derive(Debug)]
pub struct CVEDatabase {
    connection: Connection,
}

impl CVEDatabase {
    /// Inizializza il database CVE locale
    pub fn new(db_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let connection = Connection::open(db_path)?;
        
        // Create tables if they don't exist
        connection.execute(
            "CREATE TABLE IF NOT EXISTS cve_entries (
                id INTEGER PRIMARY KEY,
                cve_id TEXT UNIQUE NOT NULL,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                affected_products TEXT, -- JSON array
                affected_versions TEXT, -- JSON array
                published_date TEXT,
                modified_date TEXT,
                cve_references TEXT, -- JSON array (renamed from references)
                exploit_available INTEGER DEFAULT 0
            )",
            [],
        )?;
        
        // Indici per performance
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_cve_id ON cve_entries(cve_id)",
            [],
        )?;
        
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_products ON cve_entries(affected_products)",
            [],
        )?;
        
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_severity ON cve_entries(severity)",
            [],
        )?;
        
        Ok(CVEDatabase { connection })
    }
    
    /// Aggiorna database CVE da fonti pubbliche
    pub async fn update_database(&self) -> Result<usize, Box<dyn std::error::Error>> {
        println!("🔄 Updating CVE database from NIST...");
        
        // URL NIST CVE feed (esempio con CVE recenti)
        let nist_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000";
        
        let client = reqwest::Client::new();
        let response = client
            .get(nist_url)
            .header("User-Agent", "NextMap CVE Scanner 1.0")
            .send()
            .await?;
        
        if !response.status().is_success() {
            return Err(format!("Failed to fetch CVE data: {}", response.status()).into());
        }
        
        let json_text = response.text().await?;
        let nist_response: NISTResponse = serde_json::from_str(&json_text)?;
        
        let mut inserted = 0;
        
        for vulnerability in nist_response.vulnerabilities {
            let cve = &vulnerability.cve;
            
            // Estrai informazioni rilevanti
            let description = cve.descriptions.iter()
                .find(|d| d.lang == "en")
                .map(|d| d.value.clone())
                .unwrap_or_else(|| "No description available".to_string());
            
            let cvss_score = vulnerability.impact
                .as_ref()
                .and_then(|i| i.base_metric_v3.as_ref())
                .map(|m| m.cvss_v3.base_score)
                .unwrap_or(0.0);
            
            let severity = match cvss_score {
                s if s >= 9.0 => "Critical",
                s if s >= 7.0 => "High", 
                s if s >= 4.0 => "Medium",
                s if s > 0.0 => "Low",
                _ => "Unknown",
            }.to_string();
            
            // Estrai prodotti affetti
            let mut affected_products = Vec::new();
            if let Some(configs) = &cve.configurations {
                for config in &configs.nodes {
                    for cpe_match in &config.cpe_match {
                        if let Some(cpe23_uri) = &cpe_match.cpe23_uri {
                            // Parsing CPE per estrarre prodotto
                            if let Some(product) = parse_cpe_product(cpe23_uri) {
                                affected_products.push(product);
                            }
                        }
                    }
                }
            }
            
            // References
            let references: Vec<String> = cve.references.iter()
                .map(|r| r.url.clone())
                .collect();
            
            let cve_entry = CVEEntry {
                cve_id: cve.id.clone(),
                description,
                severity,
                cvss_score,
                affected_products: affected_products.clone(),
                affected_versions: Vec::new(), // Populated separately
                published_date: cve.published.clone(),
                modified_date: cve.last_modified.clone(),
                references,
                exploit_available: false, // Check exploit-db separately
            };
            
            if self.insert_cve(&cve_entry).is_ok() {
                inserted += 1;
            }
        }
        
        println!("✅ CVE database updated: {} new entries", inserted);
        Ok(inserted)
    }
    
    /// Inserisce CVE nel database
    fn insert_cve(&self, cve: &CVEEntry) -> SqlResult<()> {
        self.connection.execute(
            "INSERT OR REPLACE INTO cve_entries 
            (cve_id, description, severity, cvss_score, affected_products, affected_versions, 
             published_date, modified_date, cve_references, exploit_available)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            [
                &cve.cve_id,
                &cve.description,
                &cve.severity,
                &cve.cvss_score.to_string(),
                &serde_json::to_string(&cve.affected_products).unwrap_or_default(),
                &serde_json::to_string(&cve.affected_versions).unwrap_or_default(),
                &cve.published_date,
                &cve.modified_date,
                &serde_json::to_string(&cve.references).unwrap_or_default(),
                &(if cve.exploit_available { 1 } else { 0 }).to_string(),
            ],
        )?;
        Ok(())
    }
    
    /// Cerca vulnerabilità per servizio specifico
    pub fn search_vulnerabilities(&self, service: &str, version: Option<&str>) -> Result<Vec<CVEEntry>, Box<dyn std::error::Error>> {
        let mut query = "SELECT * FROM cve_entries WHERE affected_products LIKE ?1".to_string();
        let mut params: Vec<String> = vec![format!("%{}%", service.to_lowercase())];
        
        if let Some(ver) = version {
            query.push_str(" AND (affected_versions LIKE ?2 OR affected_versions = '')");
            params.push(format!("%{}%", ver));
        }
        
        query.push_str(" ORDER BY cvss_score DESC LIMIT 50");
        
        let mut stmt = self.connection.prepare(&query)?;
        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
        
        let cve_iter = stmt.query_map(&param_refs[..], |row| {
            let affected_products_json: String = row.get(5)?;
            let affected_versions_json: String = row.get(6)?;
            let references_json: String = row.get(9)?;
            
            Ok(CVEEntry {
                cve_id: row.get(1)?,
                description: row.get(2)?,
                severity: row.get(3)?,
                cvss_score: row.get(4)?,
                affected_products: serde_json::from_str(&affected_products_json).unwrap_or_default(),
                affected_versions: serde_json::from_str(&affected_versions_json).unwrap_or_default(),
                published_date: row.get(7)?,
                modified_date: row.get(8)?,
                references: serde_json::from_str(&references_json).unwrap_or_default(),
                exploit_available: row.get::<_, i32>(10)? == 1,
            })
        })?;
        
        let mut cves = Vec::new();
        for cve in cve_iter {
            cves.push(cve?);
        }
        
        Ok(cves)
    }
    
    /// Conta totale CVE nel database
    pub fn count_cves(&self) -> Result<usize, Box<dyn std::error::Error>> {
        let mut stmt = self.connection.prepare("SELECT COUNT(*) FROM cve_entries")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count as usize)
    }
    
    /// Statistiche database CVE
    pub fn get_statistics(&self) -> Result<CVEStats, Box<dyn std::error::Error>> {
        let total = self.count_cves()?;
        
        let mut stmt = self.connection.prepare(
            "SELECT severity, COUNT(*) FROM cve_entries GROUP BY severity"
        )?;
        
        let severity_iter = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        
        let mut by_severity = HashMap::new();
        for result in severity_iter {
            let (severity, count) = result?;
            by_severity.insert(severity, count as usize);
        }
        
        Ok(CVEStats {
            total_cves: total,
            by_severity,
            last_updated: chrono::Utc::now().to_rfc3339(),
        })
    }
}

/// Analizza porte aperte per vulnerabilità CVE
pub async fn scan_for_cve(
    host: &mut Host,
    cve_db: &CVEDatabase
) -> Result<(), Box<dyn std::error::Error>> {
    
    for port in &host.ports {
        if port.state != PortState::Open {
            continue;
        }
        
        if let Some(service_name) = &port.service_name {
            // Cerca CVE per questo servizio
            let cves = cve_db.search_vulnerabilities(
                service_name, 
                port.service_version.as_deref()
            )?;
            
            // Converti CVE in Vulnerability objects
            for cve in cves.into_iter().take(5) { // Limita a 5 CVE per servizio
                let vulnerability = Vulnerability {
                    cve_id: cve.cve_id,
                    severity: cve.severity,
                    description_short: if cve.description.len() > 100 {
                        format!("{}...", &cve.description[..97])
                    } else {
                        cve.description
                    },
                    service_port: port.port_id,
                };
                
                host.vulnerabilities.push(vulnerability);
            }
        }
    }
    
    Ok(())
}

/// Inizializza database CVE con dati di base
pub async fn initialize_cve_database(db_path: &str) -> Result<CVEDatabase, Box<dyn std::error::Error>> {
    let db = CVEDatabase::new(db_path)?;
    
    // Se il database è vuoto, inserisci alcuni CVE di esempio
    if db.count_cves()? == 0 {
        println!("📚 Initializing CVE database with sample data...");
        seed_sample_cves(&db)?;
    }
    
    Ok(db)
}

/// Inserisce CVE di esempio per testing
fn seed_sample_cves(db: &CVEDatabase) -> Result<(), Box<dyn std::error::Error>> {
    let sample_cves = vec![
        CVEEntry {
            cve_id: "CVE-2023-44487".to_string(),
            description: "HTTP/2 Rapid Reset Attack - Multiple implementations vulnerable to DoS".to_string(),
            severity: "High".to_string(),
            cvss_score: 7.5,
            affected_products: vec!["nginx".to_string(), "apache".to_string(), "http".to_string()],
            affected_versions: vec!["<1.25.2".to_string(), "<2.4.58".to_string()],
            published_date: "2023-10-10T00:00:00Z".to_string(),
            modified_date: "2023-10-10T00:00:00Z".to_string(),
            references: vec!["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-44487".to_string()],
            exploit_available: true,
        },
        CVEEntry {
            cve_id: "CVE-2023-20198".to_string(),
            description: "Cisco IOS XE Web UI privilege escalation vulnerability".to_string(),
            severity: "Critical".to_string(),
            cvss_score: 10.0,
            affected_products: vec!["cisco".to_string(), "ios".to_string(), "http".to_string()],
            affected_versions: vec!["*".to_string()],
            published_date: "2023-10-16T00:00:00Z".to_string(),
            modified_date: "2023-10-16T00:00:00Z".to_string(),
            references: vec!["https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z".to_string()],
            exploit_available: true,
        },
        CVEEntry {
            cve_id: "CVE-2023-22515".to_string(),
            description: "Atlassian Confluence privilege escalation vulnerability".to_string(),
            severity: "Critical".to_string(),
            cvss_score: 10.0,
            affected_products: vec!["confluence".to_string(), "atlassian".to_string(), "http".to_string()],
            affected_versions: vec!["8.0.0-8.5.3".to_string()],
            published_date: "2023-10-04T00:00:00Z".to_string(),
            modified_date: "2023-10-04T00:00:00Z".to_string(),
            references: vec!["https://confluence.atlassian.com/security/cve-2023-22515-privilege-escalation-vulnerability-in-confluence-data-center-and-server-1295682276.html".to_string()],
            exploit_available: true,
        },
        CVEEntry {
            cve_id: "CVE-2023-34362".to_string(),
            description: "MOVEit Transfer SQL injection vulnerability".to_string(),
            severity: "Critical".to_string(),
            cvss_score: 9.8,
            affected_products: vec!["moveit".to_string(), "transfer".to_string(), "http".to_string()],
            affected_versions: vec!["2019.0.0-2023.0.1".to_string()],
            published_date: "2023-06-02T00:00:00Z".to_string(),
            modified_date: "2023-06-02T00:00:00Z".to_string(),
            references: vec!["https://www.progress.com/moveit-transfer-cve-2023-34362".to_string()],
            exploit_available: true,
        },
        CVEEntry {
            cve_id: "CVE-2023-0669".to_string(),
            description: "GoAnywhere MFT authentication bypass vulnerability".to_string(),
            severity: "High".to_string(),
            cvss_score: 7.2,
            affected_products: vec!["goanywhere".to_string(), "mft".to_string(), "http".to_string()],
            affected_versions: vec!["<7.1.2".to_string()],
            published_date: "2023-02-01T00:00:00Z".to_string(),
            modified_date: "2023-02-01T00:00:00Z".to_string(),
            references: vec!["https://www.goanywhere.com/cve-2023-0669".to_string()],
            exploit_available: false,
        }
    ];
    
    for cve in sample_cves {
        db.insert_cve(&cve)?;
    }
    
    println!("✅ Sample CVE database initialized with {} entries", db.count_cves()?);
    Ok(())
}

/// Parse CPE URI per estrarre nome prodotto
fn parse_cpe_product(cpe_uri: &str) -> Option<String> {
    // CPE format: cpe:2.3:a:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    let parts: Vec<&str> = cpe_uri.split(':').collect();
    if parts.len() >= 5 && parts[0] == "cpe" {
        return Some(parts[4].to_lowercase());
    }
    None
}

#[derive(Debug)]
pub struct CVEStats {
    pub total_cves: usize,
    pub by_severity: HashMap<String, usize>,
    pub last_updated: String,
}

// Strutture per parsing NIST JSON
#[derive(Deserialize)]
struct NISTResponse {
    vulnerabilities: Vec<NISTVulnerability>,
}

#[derive(Deserialize)]
struct NISTVulnerability {
    cve: NISTCve,
    impact: Option<NISTImpact>,
}

#[derive(Deserialize)]
struct NISTCve {
    id: String,
    descriptions: Vec<NISTDescription>,
    published: String,
    #[serde(rename = "lastModified")]
    last_modified: String,
    references: Vec<NISTReference>,
    configurations: Option<NISTConfigurations>,
}

#[derive(Deserialize)]
struct NISTDescription {
    lang: String,
    value: String,
}

#[derive(Deserialize)]
struct NISTReference {
    url: String,
}

#[derive(Deserialize)]
struct NISTConfigurations {
    nodes: Vec<NISTNode>,
}

#[derive(Deserialize)]
struct NISTNode {
    #[serde(rename = "cpeMatch")]
    cpe_match: Vec<NISTCpeMatch>,
}

#[derive(Deserialize)]
struct NISTCpeMatch {
    #[serde(rename = "cpe23Uri")]
    cpe23_uri: Option<String>,
}

#[derive(Deserialize)]
struct NISTImpact {
    #[serde(rename = "baseMetricV3")]
    base_metric_v3: Option<NISTBaseMetricV3>,
}

#[derive(Deserialize)]
struct NISTBaseMetricV3 {
    #[serde(rename = "cvssV3")]
    cvss_v3: NISTCVSSV3,
}

#[derive(Deserialize)]
struct NISTCVSSV3 {
    #[serde(rename = "baseScore")]
    base_score: f32,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_cve_database_creation() {
        let db = CVEDatabase::new(":memory:").expect("Failed to create test database");
        assert_eq!(db.count_cves().unwrap(), 0);
    }
    
    #[test]
    fn test_cpe_parsing() {
        let cpe = "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*";
        assert_eq!(parse_cpe_product(cpe), Some("http_server".to_string()));
        
        let invalid_cpe = "invalid:cpe:string";
        assert_eq!(parse_cpe_product(invalid_cpe), None);
    }
}