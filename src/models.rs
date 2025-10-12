// src/models.rs

use serde::{Serialize, Deserialize};

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