// src/models.rs

use serde::{Serialize, Deserialize};

// --- Enumerazioni per Enhanced Output Formatting ---

/// Categoria del servizio per raggruppamento logico
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub enum ServiceCategory {
    Web,              // HTTP, HTTPS, Web servers
    Database,         // MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, etc.
    MessageQueue,     // RabbitMQ, Kafka, MQTT, ActiveMQ
    Container,        // Docker, Kubernetes
    Cache,            // Redis, Memcached
    Storage,          // MinIO, CouchDB
    Search,           // Elasticsearch, Solr
    Configuration,    // etcd, Consul, Zookeeper
    Security,         // Vault
    Email,            // SMTP, POP3, IMAP
    FileTransfer,     // FTP, SSH, SFTP
    RemoteAccess,     // SSH, RDP, VNC, Telnet
    Directory,        // LDAP, Active Directory
    Monitoring,       // SNMP
    Other,            // Servizi non categorizzati
}

/// Livello di rischio del servizio esposto
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Critical,  // Servizi critici (Telnet, FTP non criptati, servizi con CVE critici)
    High,      // Servizi ad alto rischio (DB esposti, admin panels, container APIs)
    Medium,    // Servizi potenzialmente rischiosi (web servers, cache)
    Low,       // Servizi a basso rischio (servizi interni, versioni aggiornate)
    Info,      // Solo informativo (porte filtrate, banner limitati)
}

/// Metodo utilizzato per la detection del servizio
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DetectionMethod {
    Banner,           // Banner grabbing standard
    EnhancedProbe,    // Probe HTTP/JSON API attivo
    VersionProbe,     // Probe specifico per versione
    PortMapping,      // Inferenza da porta standard
    ActiveScan,       // Active vulnerability scanning (Nuclei)
    Unknown,          // Metodo non determinato
}

// --- Strutture principali ---

#[derive(Serialize, Deserialize, Debug)]
pub struct ScanResult {
    // La macro `with` usa il formatter ISO 8601 di chrono
    pub timestamp: String, 
    pub command: String,
    pub duration_ms: u64,
    pub hosts: Vec<Host>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Host {
    pub ip_address: String,
    pub hostname: Option<String>,
    pub status: HostStatus,
    pub ports: Vec<Port>,
    // Opzioni (-O)
    pub os_details: Option<OSDetails>, 
    // Opzioni (-sV)
    pub vulnerabilities: Vec<Vulnerability>, 
}

// --- Enumerazioni ---

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum HostStatus {
    Up,
    Down,
    Filtered,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered, 
}

// --- Strutture di dettaglio ---

#[derive(Serialize, Deserialize, Debug)]
pub struct Port {
    pub port_id: u16,
    pub protocol: String,
    pub state: PortState,
    pub service_name: Option<String>,
    pub service_version: Option<String>,
    pub banner: Option<String>,
    
    // Enhanced Output Formatting - Metadata aggiuntivi
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_category: Option<ServiceCategory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<RiskLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection_method: Option<DetectionMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cve_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_banner: Option<String>, // Banner completo (non troncato)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Vulnerability {
    pub cve_id: String,
    pub severity: String,
    pub description_short: String,
    pub service_port: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OSDetails {
    pub os_vendor: Option<String>,
    pub os_family: Option<String>,
    pub accuracy: u8, // Punteggio 0-100
    pub ttl_hop_distance: u8,
}

// --- Helper functions per Enhanced Output Formatting ---

impl ServiceCategory {
    /// Determina la categoria del servizio in base a nome e porta
    pub fn from_service(service_name: &str, port: u16) -> Self {
        let service_lower = service_name.to_lowercase();
        
        // Database services
        if service_lower.contains("mysql") 
            || service_lower.contains("postgresql") 
            || service_lower.contains("mongodb")
            || service_lower.contains("cassandra")
            || service_lower.contains("couchdb")
            || service_lower.contains("mssql")
            || port == 3306 || port == 5432 || port == 27017 || port == 9042 || port == 5984 || port == 1433 {
            return ServiceCategory::Database;
        }
        
        // Cache services
        if service_lower.contains("redis") 
            || service_lower.contains("memcached")
            || port == 6379 || port == 11211 {
            return ServiceCategory::Cache;
        }
        
        // Search engines
        if service_lower.contains("elasticsearch") 
            || service_lower.contains("solr")
            || port == 9200 || port == 9300 || port == 8983 {
            return ServiceCategory::Search;
        }
        
        // Message Queue services
        if service_lower.contains("rabbitmq") 
            || service_lower.contains("kafka")
            || service_lower.contains("mqtt")
            || service_lower.contains("activemq")
            || port == 5672 || port == 9092 || port == 1883 || port == 8883 || port == 61616 {
            return ServiceCategory::MessageQueue;
        }
        
        // Container services
        if service_lower.contains("docker") 
            || service_lower.contains("kubernetes")
            || service_lower.contains("k8s")
            || port == 2375 || port == 2376 || port == 6443 || port == 10250 {
            return ServiceCategory::Container;
        }
        
        // Configuration/Orchestration services
        if service_lower.contains("etcd") 
            || service_lower.contains("consul")
            || service_lower.contains("zookeeper")
            || port == 2379 || port == 2380 || port == 8500 || port == 2181 {
            return ServiceCategory::Configuration;
        }
        
        // Security/Secrets management
        if service_lower.contains("vault") || port == 8200 {
            return ServiceCategory::Security;
        }
        
        // Storage services
        if service_lower.contains("minio") 
            || service_lower.contains("s3")
            || port == 9000 {
            return ServiceCategory::Storage;
        }
        
        // Web services
        if service_lower.contains("http") 
            || service_lower.contains("https")
            || service_lower.contains("web")
            || service_lower.contains("nginx")
            || service_lower.contains("apache")
            || service_lower.contains("express")
            || service_lower.contains("django")
            || service_lower.contains("spring")
            || port == 80 || port == 443 || port == 8080 || port == 8443 || port == 3000 {
            return ServiceCategory::Web;
        }
        
        // Email services
        if service_lower.contains("smtp") 
            || service_lower.contains("pop3")
            || service_lower.contains("imap")
            || port == 25 || port == 110 || port == 143 || port == 587 || port == 993 || port == 995 {
            return ServiceCategory::Email;
        }
        
        // File Transfer
        if service_lower.contains("ftp") 
            || service_lower.contains("sftp")
            || service_lower.contains("ssh")
            || port == 21 || port == 22 || port == 115 {
            return ServiceCategory::FileTransfer;
        }
        
        // Remote Access
        if service_lower.contains("ssh") 
            || service_lower.contains("rdp")
            || service_lower.contains("vnc")
            || service_lower.contains("telnet")
            || port == 22 || port == 3389 || port == 5900 || port == 23 {
            return ServiceCategory::RemoteAccess;
        }
        
        // Directory services
        if service_lower.contains("ldap") 
            || service_lower.contains("active directory")
            || port == 389 || port == 636 {
            return ServiceCategory::Directory;
        }
        
        // Monitoring
        if service_lower.contains("snmp") || port == 161 || port == 162 {
            return ServiceCategory::Monitoring;
        }
        
        ServiceCategory::Other
    }
    
    /// Restituisce il nome human-readable della categoria
    pub fn display_name(&self) -> &str {
        match self {
            ServiceCategory::Web => "Web Server",
            ServiceCategory::Database => "Database",
            ServiceCategory::MessageQueue => "Message Queue",
            ServiceCategory::Container => "Container/Orchestration",
            ServiceCategory::Cache => "Cache",
            ServiceCategory::Storage => "Object Storage",
            ServiceCategory::Search => "Search Engine",
            ServiceCategory::Configuration => "Configuration/Service Discovery",
            ServiceCategory::Security => "Security/Secrets",
            ServiceCategory::Email => "Email",
            ServiceCategory::FileTransfer => "File Transfer",
            ServiceCategory::RemoteAccess => "Remote Access",
            ServiceCategory::Directory => "Directory Service",
            ServiceCategory::Monitoring => "Monitoring",
            ServiceCategory::Other => "Other",
        }
    }
}

impl RiskLevel {
    /// Calcola il livello di rischio basato su servizio, porta, CVE e versione
    pub fn calculate(
        service_name: &str, 
        port: u16, 
        category: &ServiceCategory,
        has_version: bool,
        cve_count: usize
    ) -> Self {
        let service_lower = service_name.to_lowercase();
        
        // CRITICAL: Servizi intrinsecamente non sicuri
        if service_lower.contains("telnet") 
            || (service_lower.contains("ftp") && !service_lower.contains("sftp"))
            || port == 23 
            || (port == 21 && !service_lower.contains("sftp"))
            || cve_count >= 5 {
            return RiskLevel::Critical;
        }
        
        // HIGH: Servizi critici esposti pubblicamente
        if matches!(category, 
            ServiceCategory::Database | 
            ServiceCategory::Container | 
            ServiceCategory::Configuration |
            ServiceCategory::Security
        ) || cve_count >= 3 {
            return RiskLevel::High;
        }
        
        // HIGH: Porte admin/management esposte
        if port == 2375 || port == 2376  // Docker
            || port == 6443 || port == 10250  // Kubernetes
            || port == 9200 || port == 9300  // Elasticsearch
            || port == 27017  // MongoDB
            || port == 5984   // CouchDB
            || port == 8500   // Consul
            || port == 8200 { // Vault
            return RiskLevel::High;
        }
        
        // MEDIUM: Servizi con versione sconosciuta o CVE presenti
        if !has_version || cve_count >= 1 {
            return RiskLevel::Medium;
        }
        
        // MEDIUM: Message Queue, Cache, Search esposti
        if matches!(category,
            ServiceCategory::MessageQueue |
            ServiceCategory::Cache |
            ServiceCategory::Search |
            ServiceCategory::Storage
        ) {
            return RiskLevel::Medium;
        }
        
        // LOW: Servizi standard con versione nota
        if matches!(category,
            ServiceCategory::Web |
            ServiceCategory::Email
        ) && has_version {
            return RiskLevel::Low;
        }
        
        // Default: LOW
        RiskLevel::Low
    }
    
    /// Restituisce il colore ANSI per il terminale
    pub fn ansi_color(&self) -> &str {
        match self {
            RiskLevel::Critical => "\x1b[91m", // Rosso brillante
            RiskLevel::High => "\x1b[31m",     // Rosso
            RiskLevel::Medium => "\x1b[33m",   // Giallo
            RiskLevel::Low => "\x1b[32m",      // Verde
            RiskLevel::Info => "\x1b[36m",     // Cyan
        }
    }
    
    /// Restituisce il codice colore HTML
    pub fn html_color(&self) -> &str {
        match self {
            RiskLevel::Critical => "#dc3545", // Bootstrap danger
            RiskLevel::High => "#fd7e14",     // Bootstrap warning dark
            RiskLevel::Medium => "#ffc107",   // Bootstrap warning
            RiskLevel::Low => "#28a745",      // Bootstrap success
            RiskLevel::Info => "#17a2b8",     // Bootstrap info
        }
    }
    
    /// Restituisce il simbolo per il livello di rischio
    pub fn symbol(&self) -> &str {
        match self {
            RiskLevel::Critical => "🔴",
            RiskLevel::High => "🟠",
            RiskLevel::Medium => "🟡",
            RiskLevel::Low => "🟢",
            RiskLevel::Info => "🔵",
        }
    }
}

impl DetectionMethod {
    /// Restituisce il nome human-readable del metodo
    pub fn display_name(&self) -> &str {
        match self {
            DetectionMethod::Banner => "Banner Grabbing",
            DetectionMethod::EnhancedProbe => "Enhanced Probe",
            DetectionMethod::VersionProbe => "Version Probe",
            DetectionMethod::PortMapping => "Port Mapping",
            DetectionMethod::ActiveScan => "Active Scan (Nuclei)",
            DetectionMethod::Unknown => "Unknown",
        }
    }
}