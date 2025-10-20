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
mod fingerprint;
mod output;
#[cfg(feature = "network-discovery")]
mod discovery;

use models::*;
use stealth::*;
use cve::*;
use fingerprint::*;
#[cfg(feature = "network-discovery")]
use discovery::*;

// Import Enhanced Output types
use models::{ServiceCategory, RiskLevel, DetectionMethod}; 

// --- CLI Configuration with clap ---

#[derive(Parser, Debug)]
#[command(author = "NextMap Dev Team", version, about = "🔍 Next generation network scanner with stealth capabilities and CVE detection.", long_about = None)]
struct Args {
    /// Target IP, IP range (e.g., 192.168.1.1-254) or CIDR (e.g., 192.168.1.0/24) to scan
    #[arg(short, long)]
    target: String,

    /// Ports to scan (e.g., "80,443,22-25", or "top100", "top1000", "top5000", "all")
    #[arg(short, long, default_value = "top1000")]
    ports: String,
    
    /// Smart port selection for specific OS/environment (windows, linux, cloud, iot)
    #[arg(long)]
    smart_ports: Option<String>,
    
    /// Enable service detection and vulnerability analysis
    #[arg(short = 's', long, default_value_t = false)]
    service_scan: bool, 
    
    /// Enable OS fingerprinting
    #[arg(short = 'O', long, default_value_t = false)]
    os_scan: bool,
    
    /// Output format (human, json, yaml, xml, csv, md, html)
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

    #[cfg(feature = "network-discovery")]
    /// Enable network discovery mode (ARP scan, ping sweep, neighbor discovery)
    #[arg(long, default_value_t = false)]
    network_discovery: bool,

    #[cfg(feature = "network-discovery")]
    /// Network discovery timeout in milliseconds
    #[arg(long, default_value_t = 1000)]
    discovery_timeout: u64,

    #[cfg(feature = "network-discovery")]
    /// Include loopback interfaces in network discovery
    #[arg(long, default_value_t = false)]
    include_loopback: bool,

    #[cfg(feature = "network-discovery")]
    /// Aggressive network discovery mode (faster but more noticeable)
    #[arg(long, default_value_t = false)]
    aggressive_discovery: bool,
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

// --- Port Lists (nmap-style) ---

// Top 100 most common TCP ports (similar to nmap --top-ports 100)
fn get_top_100_ports() -> Vec<u16> {
    vec![
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
        139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
        554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433,
        1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986,
        4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
        6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
        49152, 49153, 49154, 49155, 49156, 49157
    ]
}

// Top 1000 most common TCP ports (similar to nmap default)
// Enhanced with Windows-specific ports: 67, 68, 137, 138, 5985, 5986, 8530, 8531, 9389, 47001
fn get_top_1000_ports() -> Vec<u16> {
    vec![
        1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53,
        67, 68, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125,
        135, 137, 138, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280,
        301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465,
        481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593,
        616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720,
        722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902,
        903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010,
        1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034,
        1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049,
        1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064,
        1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079,
        1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094,
        1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108, 1110, 1111, 1112,
        1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132, 1137, 1138, 1141,
        1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175, 1183,
        1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244,
        1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328,
        1334, 1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533,
        1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718, 1719, 1720,
        1721, 1723, 1755, 1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875,
        1900, 1914, 1935, 1947, 1971, 1972, 1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004,
        2005, 2006, 2007, 2008, 2009, 2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038,
        2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105,
        2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196,
        2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401,
        2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710,
        2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910, 2920, 2967, 2968, 2998, 3000,
        3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052, 3071, 3077, 3128, 3168,
        3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333,
        3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527, 3546, 3551,
        3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828,
        3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998,
        4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279,
        4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998, 5000,
        5001, 5002, 5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100,
        5101, 5102, 5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405,
        5414, 5431, 5432, 5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678,
        5679, 5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877,
        5900, 5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959,
        5960, 5961, 5962, 5963, 5985, 5986, 5987, 5988, 5989, 5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005,
        6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502,
        6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699,
        6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019, 7025,
        7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741,
        7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002, 8007, 8008, 8009,
        8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087,
        8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254, 8290,
        8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8530, 8531, 8600, 8649, 8651, 8652, 8654, 8701,
        8800, 8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071,
        9080, 9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290,
        9389, 9415, 9418, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877,
        9878, 9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003,
        10004, 10009, 10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566, 10616, 10617,
        10621, 10626, 10628, 10629, 10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456,
        13722, 13782, 13783, 14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742,
        16000, 16001, 16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101,
        18988, 19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222,
        20828, 21571, 22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353, 27355,
        27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337, 32768, 32769, 32770, 32771, 32772,
        32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785,
        33354, 33899, 34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176, 44442,
        44443, 44501, 45100, 47001, 48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160,
        49161, 49163, 49165, 49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003, 50006,
        50300, 50389, 50500, 50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328,
        55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900,
        62078, 63331, 64623, 64680, 65000, 65129, 65389
    ]
}

// Top 5000 most common TCP ports (comprehensive enterprise coverage)
// Provides ~99.9% coverage of commonly used services
fn get_top_5000_ports() -> Vec<u16> {
    // Start with top1000 and extend with additional enterprise ports
    let mut ports = get_top_1000_ports();
    
    // Additional enterprise and specialized service ports
    let additional_ports: Vec<u16> = vec![
        // Extended web services
        81, 280, 591, 593, 2301, 2381, 3000, 4567, 5800, 5801, 5802, 7000, 7001, 7002,
        // Extended databases
        1521, 1830, 2483, 2484, 3050, 3351, 4333, 5984, 6379, 7474, 8086, 8529, 9042,
        // Extended Windows services
        1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037,
        1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050,
        5722, 5723, 6001, 6002, 6003, 6004, 6005, 6006, 9535,
        // Cloud & container services
        2375, 2376, 2377, 4243, 6443, 8001, 8002, 8003, 8443, 9000, 9091, 9093, 9094,
        10250, 10251, 10252, 10255, 10256, 30000, 30001, 30002, 31000, 32000,
        // DevOps & CI/CD
        8081, 8082, 8090, 8091, 8111, 8200, 8300, 8400, 8500, 8888, 9090, 9091, 50000,
        // Monitoring & logging
        3000, 4000, 5044, 5144, 5601, 8125, 8126, 9200, 9300, 9600, 9999, 24224,
        // Message queues
        4369, 5672, 5673, 9092, 9093, 9094, 15672, 25672, 61613, 61614, 61616,
        // VoIP & streaming
        1719, 1720, 3478, 5004, 5005, 5060, 5061, 5349, 5350, 7070,
        // IoT & embedded
        1883, 8883, 8080, 48899, 49153, 55443,
        // Backup & storage
        2049, 3260, 3262, 10000, 10001, 10002,
        // Remote access (extended)
        5800, 5900, 5901, 5902, 5903, 6000, 6001, 6002, 6003, 22939,
        // Gaming
        3074, 7777, 7778, 25565, 25575, 27015, 27016, 27017, 28960,
        // Custom application ports
        3001, 3002, 3003, 4000, 4001, 4002, 4003, 4004, 4005, 4006,
        5001, 5002, 5003, 5004, 5005, 5006, 5007, 5008, 5009, 5010,
        6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009, 6010,
        7001, 7002, 7003, 7004, 7005, 7006, 7007, 7008, 7009, 7010,
        8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010,
        9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, 9010,
        // Extended ephemeral Windows ports
        49200, 49201, 49202, 49203, 49204, 49205, 49206, 49207, 49208, 49209,
        49210, 49211, 49212, 49213, 49214, 49215, 49216, 49217, 49218, 49219,
        // Additional service ports filling to ~5000
        143, 220, 465, 512, 513, 514, 515, 543, 544, 548, 617, 631, 873, 1080,
        1433, 1434, 1723, 2100, 2121, 2375, 2376, 2382, 2383, 3128, 3268, 3269,
        3306, 3389, 4444, 5000, 5432, 5555, 5900, 6000, 6379, 6666, 7001, 7777,
        8000, 8080, 8081, 8088, 8443, 8888, 9000, 9001, 9200, 9999, 10000,
        11211, 12345, 27017, 27018, 27019, 50000, 50070, 60010, 60020, 60030,
    ];
    
    // Merge and remove duplicates
    ports.extend(additional_ports);
    ports.sort_unstable();
    ports.dedup();
    
    // Extend to approximately 5000 ports by adding sequential ranges
    let current_len = ports.len();
    if current_len < 5000 {
        // Add sequential ports from common ranges
        for port in 1..=10000 {
            if !ports.contains(&port) && ports.len() < 5000 {
                ports.push(port);
            }
        }
        ports.sort_unstable();
    }
    
    // Ensure we return exactly top 5000
    ports.truncate(5000);
    ports
}

// Smart port selection for Windows environments
// ~150 ports optimized for Windows services
fn get_windows_smart_ports() -> Vec<u16> {
    vec![
        // Remote Access & Management
        22, 23, 3389, 5985, 5986, 47001,
        // File Sharing & SMB
        135, 137, 138, 139, 445,
        // Active Directory & Domain Services
        88, 389, 464, 636, 3268, 3269, 9389,
        // DNS & DHCP
        53, 67, 68,
        // Email (Exchange)
        25, 110, 143, 465, 587, 993, 995,
        // Web Services (IIS)
        80, 443, 8080, 8443,
        // MSSQL
        1433, 1434,
        // RPC & Windows Services
        593, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032,
        5722, 5723,
        // Windows Update & WSUS
        8530, 8531,
        // Remote Desktop Services
        3389, 5985, 5986,
        // Other Windows Services
        1900, 2179, 5357,
        // Ephemeral ports (Windows dynamic range)
        49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161,
        // VMware on Windows
        902, 903, 912,
        // Common application ports
        21, 161, 443, 1433, 3306, 5432, 8080, 9090,
    ]
}

// Smart port selection for Linux environments
// ~120 ports optimized for Linux services
fn get_linux_smart_ports() -> Vec<u16> {
    vec![
        // Remote Access
        20, 21, 22, 23, 2222,
        // Web Services
        80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090,
        // Mail Services
        25, 110, 143, 465, 587, 993, 995,
        // DNS
        53,
        // Databases
        3306, 3307, 5432, 27017, 27018, 27019, 28017, 6379, 11211,
        // NoSQL Databases
        5984, 7000, 7001, 7199, 8086, 8091, 8092, 8093, 8529, 9042, 9160, 9200, 9300,
        // NFS & Samba
        111, 2049, 139, 445,
        // Remote Desktop
        5900, 5901, 5902, 5903, 6000, 6001, 6002,
        // Monitoring
        3000, 9090, 9091, 9093, 9094, 9100, 9115, 9116,
        // Message Queues
        4369, 5672, 5673, 9092, 9093, 15672, 25672, 61613, 61614, 61616,
        // Container & Orchestration
        2375, 2376, 2377, 4243, 6443, 8001, 8080, 9090, 9093, 10250, 10251, 10252, 10255,
        // Development
        3000, 3001, 4000, 5000, 8000, 8001, 8080, 8081, 9000,
    ]
}

// Smart port selection for Cloud/Container environments
// ~100 ports optimized for cloud services
fn get_cloud_smart_ports() -> Vec<u16> {
    vec![
        // SSH & Remote Access
        22, 2222,
        // Web Services
        80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090,
        // Docker
        2375, 2376, 2377, 4243, 5000,
        // Kubernetes
        6443, 8001, 8080, 9090, 9093, 9094, 10250, 10251, 10252, 10255, 10256, 30000, 31000,
        // Databases (managed)
        3306, 5432, 6379, 9042, 9200, 27017,
        // Load Balancers
        80, 443, 8080, 8443,
        // Monitoring & Logging
        3000, 4000, 5044, 5601, 8086, 8125, 8126, 9090, 9093, 9200, 9300, 24224,
        // Message Queues
        5672, 9092, 15672, 61613,
        // API Gateways
        8000, 8001, 8080, 8081, 9000, 50000,
        // Service Mesh
        15000, 15001, 15006, 15010, 15014, 15020, 15021, 15090,
        // Consul
        8300, 8301, 8302, 8500, 8600,
        // Vault
        8200, 8201,
        // Elasticsearch
        9200, 9300,
        // Prometheus & Grafana
        3000, 9090, 9091,
        // CI/CD
        8080, 8081, 8111, 8443, 9000, 50000,
    ]
}

// Smart port selection for IoT/Embedded devices
// ~80 ports optimized for IoT and embedded systems
fn get_iot_smart_ports() -> Vec<u16> {
    vec![
        // Basic services
        21, 22, 23, 80, 81, 443, 8080, 8081, 8443, 9000,
        // Telnet variants
        23, 2323, 9999,
        // Web interfaces
        80, 81, 443, 554, 8000, 8080, 8081, 8090, 8443, 8888, 9000, 10001,
        // RTSP (cameras)
        554, 8554,
        // MQTT (IoT messaging)
        1883, 8883,
        // UPnP
        1900, 5000,
        // mDNS/Bonjour
        5353,
        // CoAP
        5683, 5684,
        // Common IoT web ports
        80, 81, 88, 443, 8000, 8008, 8080, 8081, 8090, 8443, 8888, 9000, 9001,
        // Camera/DVR ports
        37777, 34567, 8000, 9000, 48899, 55443,
        // Router admin
        80, 443, 8080, 8081, 8888,
        // Smart home
        1900, 5000, 8080, 8883, 9000,
        // Industrial IoT
        102, 502, 2404, 20000, 44818, 47808, 50000,
        // Printer services
        515, 631, 9100,
    ]
}

// Parse porte (supporta ranges come 22-25, preset: top100, top1000, top5000, all)
fn parse_ports(ports_input: &str) -> Result<Vec<u16>, Box<dyn std::error::Error>> {
    let mut ports = Vec::new();
    
    // Handle preset values
    match ports_input.trim().to_lowercase().as_str() {
        "top100" => return Ok(get_top_100_ports()),
        "top1000" => return Ok(get_top_1000_ports()),
        "top5000" => return Ok(get_top_5000_ports()),
        "all" => return Ok((1..=65535).collect()),
        _ => {}
    }
    
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
        service_category: None,
        risk_level: None,
        detection_method: None,
        cve_count: None,
        full_banner: None,
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
        service_category: None,
        risk_level: None,
        detection_method: None,
        cve_count: None,
        full_banner: None,
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

// Sanitize banner string - remove non-printable characters
fn sanitize_banner(data: &[u8]) -> String {
    data.iter()
        .filter_map(|&byte| {
            match byte {
                // Printable ASCII (letters, numbers, common punctuation)
                32..=126 => Some(byte as char),
                // Tab, preserve as space
                9 => Some(' '),
                // LF and CR, keep for line breaks
                10 | 13 => Some(byte as char),
                // Everything else is discarded
                _ => None,
            }
        })
        .collect::<String>()
        .trim()
        .to_string()
}

// Banner grabbing per identificazione servizi
async fn grab_banner(stream: &mut TcpStream, port: u16, timeout: Duration) -> Option<String> {
    let mut buffer = [0; 4096]; // Aumentato per risposte più grandi
    
    // Per alcuni servizi, dobbiamo inviare un comando/probe
    let probe = match port {
        // HTTP
        80 | 8080 => Some("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
        
        // FTP, SSH, SMTP inviano banner automaticamente
        21 | 22 | 25 | 110 | 143 => None,
        
        // Redis - INFO command
        6379 => Some("INFO\r\n"),
        
        // Memcached - VERSION command
        11211 => Some("version\r\n"),
        
        // Zookeeper - stat command
        2181 => Some("stat\n"),
        
        // MongoDB - simple query
        27017 => Some("{ \"ping\": 1 }\r\n"),
        
        // Elasticsearch, Docker, Kubernetes, etcd, CouchDB, Solr, Consul, Vault - handled by enhanced_fingerprint via HTTP
        9200 | 2375 | 2376 | 6443 | 2379 | 2380 | 5984 | 8983 | 8500 | 8200 => None,
        
        // RabbitMQ - AMQP handshake (management API handled by enhanced_fingerprint)
        5672 => None,
        
        // Kafka, MQTT, Cassandra - binary protocols, handled by enhanced_fingerprint
        9092 | 1883 | 8883 | 9042 => None,
        
        // HTTP alternatives
        8000..=8999 => Some("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
        
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
            // Sanitize the banner to remove non-printable characters
            let cleaned = sanitize_banner(&buffer[..n]);
            
            // Take the first non-empty line or full response for JSON/structured data
            let response = cleaned.trim().to_string();
            
            if !response.is_empty() {
                Some(response)
            } else {
                None
            }
        }
        _ => None,
    }
}

// HTTP probe per servizi JSON-based (Elasticsearch, Docker, Kubernetes, etc.)
async fn probe_http_service(target: &str, port: u16, endpoint: &str, timeout: Duration) -> Option<String> {
    let socket_addr = format!("{}:{}", target, port);
    
    match tokio::time::timeout(timeout, TcpStream::connect(&socket_addr)).await {
        Ok(Ok(mut stream)) => {
            // Costruisci richiesta HTTP GET
            let request = format!(
                "GET {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: NextMap/0.3.1\r\nConnection: close\r\n\r\n",
                endpoint, target, port
            );
            
            if stream.write_all(request.as_bytes()).await.is_err() {
                return None;
            }
            
            let mut buffer = Vec::new();
            match tokio::time::timeout(timeout, stream.read_to_end(&mut buffer)).await {
                Ok(Ok(_)) if !buffer.is_empty() => {
                    // Converti in stringa
                    let response = String::from_utf8_lossy(&buffer);
                    
                    // Estrai solo il body (dopo le header HTTP)
                    if let Some(body_start) = response.find("\r\n\r\n") {
                        let body = &response[body_start + 4..];
                        if !body.is_empty() {
                            return Some(body.to_string());
                        }
                    }
                    
                    None
                }
                _ => None,
            }
        }
        _ => None,
    }
}

// Probe binario per servizi come Redis, Memcached
async fn probe_text_protocol(target: &str, port: u16, command: &str, timeout: Duration) -> Option<String> {
    let socket_addr = format!("{}:{}", target, port);
    
    match tokio::time::timeout(timeout, TcpStream::connect(&socket_addr)).await {
        Ok(Ok(mut stream)) => {
            // Invia comando
            if stream.write_all(command.as_bytes()).await.is_err() {
                return None;
            }
            
            let mut buffer = [0; 4096];
            match tokio::time::timeout(timeout, stream.read(&mut buffer)).await {
                Ok(Ok(n)) if n > 0 => {
                    Some(String::from_utf8_lossy(&buffer[..n]).to_string())
                }
                _ => None,
            }
        }
        _ => None,
    }
}

// Probe binario per protocolli come Kafka, MQTT, Cassandra
async fn probe_binary_protocol(target: &str, port: u16, probe_data: &[u8], timeout: Duration) -> Option<Vec<u8>> {
    let socket_addr = format!("{}:{}", target, port);
    
    match tokio::time::timeout(timeout, TcpStream::connect(&socket_addr)).await {
        Ok(Ok(mut stream)) => {
            // Invia probe
            if stream.write_all(probe_data).await.is_err() {
                return None;
            }
            
            let mut buffer = vec![0; 1024];
            match tokio::time::timeout(timeout, stream.read(&mut buffer)).await {
                Ok(Ok(n)) if n > 0 => {
                    buffer.truncate(n);
                    Some(buffer)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

// Enhanced fingerprinting con supporto per tutti i 20+ protocolli
async fn enhanced_fingerprint(target: &str, port: u16, service_name: &str, banner: Option<&str>, timeout: Duration) -> Option<String> {
    match service_name {
        // Redis - INFO command
        "redis" if banner.is_none() => {
            if let Some(response) = probe_text_protocol(target, port, "INFO\r\n", timeout).await {
                return fingerprint::extract_redis_version(&response);
            }
        }
        
        // Memcached - VERSION command  
        "memcached" | "memcache" if banner.is_none() => {
            if let Some(response) = probe_text_protocol(target, port, "version\r\n", timeout).await {
                return fingerprint::extract_memcached_version(&response);
            }
        }
        
        // Zookeeper - stat command
        "zookeeper" if banner.is_none() => {
            if let Some(response) = probe_text_protocol(target, port, "stat\n", timeout).await {
                return fingerprint::extract_zookeeper_version(&response);
            }
        }
        
        // Elasticsearch - cluster health API
        "elasticsearch" => {
            if let Some(json) = probe_http_service(target, port, "/_cluster/health", timeout).await {
                if let Some((version, cluster)) = fingerprint::extract_elasticsearch_info(&json) {
                    return Some(format!("{} (cluster: {})", version, cluster));
                }
            }
        }
        
        // Docker API - /version endpoint
        "docker" => {
            if let Some(json) = probe_http_service(target, port, "/version", timeout).await {
                if let Some((version, api_ver)) = fingerprint::extract_docker_version(&json) {
                    return Some(format!("{} (API: {})", version, api_ver));
                }
            }
        }
        
        // Kubernetes API - /version
        "kubernetes" | "k8s" => {
            if let Some(json) = probe_http_service(target, port, "/version", timeout).await {
                return fingerprint::extract_kubernetes_version(&json);
            }
        }
        
        // etcd API - /version
        "etcd" => {
            if let Some(json) = probe_http_service(target, port, "/version", timeout).await {
                return fingerprint::extract_etcd_version(&json);
            }
        }
        
        // CouchDB - root endpoint
        "couchdb" => {
            if let Some(json) = probe_http_service(target, port, "/", timeout).await {
                return fingerprint::extract_couchdb_version(&json);
            }
        }
        
        // Apache Solr - admin info
        "solr" => {
            if let Some(json) = probe_http_service(target, port, "/solr/admin/info/system", timeout).await {
                return fingerprint::extract_solr_version(&json);
            }
        }
        
        // HashiCorp Consul - agent API
        "consul" => {
            if let Some(json) = probe_http_service(target, port, "/v1/agent/self", timeout).await {
                return fingerprint::extract_consul_version(&json);
            }
        }
        
        // HashiCorp Vault - health endpoint
        "vault" => {
            if let Some(json) = probe_http_service(target, port, "/v1/sys/health", timeout).await {
                return fingerprint::extract_vault_version(&json);
            }
        }
        
        // Kafka - ApiVersions request (simplified)
        "kafka" if banner.is_none() => {
            // Kafka ApiVersions request (API key 18, version 0)
            let probe: Vec<u8> = vec![
                0x00, 0x00, 0x00, 0x12, // Request size
                0x00, 0x12, // API key (ApiVersions = 18)
                0x00, 0x00, // API version
                0x00, 0x00, 0x00, 0x01, // Correlation ID
                0x00, 0x08, // Client ID length
                b'n', b'e', b'x', b't', b'm', b'a', b'p', b' ', // "nextmap "
            ];
            
            if let Some(response) = probe_binary_protocol(target, port, &probe, timeout).await {
                return fingerprint::extract_kafka_version(&response);
            }
        }
        
        // MQTT - CONNECT packet
        "mqtt" if banner.is_none() => {
            // MQTT CONNECT packet (simplified)
            let connect_packet: Vec<u8> = vec![
                0x10, 0x10, // CONNECT, remaining length
                0x00, 0x04, b'M', b'Q', b'T', b'T', // Protocol name
                0x04, // Protocol level (3.1.1)
                0x02, // Connect flags (clean session)
                0x00, 0x3c, // Keep alive (60 seconds)
                0x00, 0x00, // Client ID length (empty)
            ];
            
            if let Some(response) = probe_binary_protocol(target, port, &connect_packet, timeout).await {
                return fingerprint::extract_mqtt_version(&response);
            }
        }
        
        // Cassandra - OPTIONS frame
        "cassandra" if banner.is_none() => {
            // Cassandra OPTIONS request (protocol v4)
            let options_frame: Vec<u8> = vec![
                0x04, // Version (v4)
                0x00, // Flags
                0x00, 0x01, // Stream ID
                0x05, // Opcode (OPTIONS)
                0x00, 0x00, 0x00, 0x00, // Body length
            ];
            
            if let Some(response) = probe_binary_protocol(target, port, &options_frame, timeout).await {
                return fingerprint::extract_cassandra_version(&response);
            }
        }
        
        _ => {}
    }
    
    // Se abbiamo un banner, usa extract_service_version standard
    if let Some(banner_str) = banner {
        return fingerprint::extract_service_version(service_name, banner_str);
    }
    
    None
}

// Mappatura di base dei servizi (senza banner grabbing)
async fn map_basic_service(mut port: Port) -> (Port, Vec<Vulnerability>) {
    let mut vulns = Vec::new();
    
    if port.state == PortState::Open {
        // Identificazione servizi basata solo su porte standard
        match (port.port_id, port.protocol.as_str()) {
            // Servizi TCP comuni
            (21, "tcp") => {
                port.service_name = Some("ftp".to_string());
                port.service_version = Some("FTP Server".to_string());
            }
            (22, "tcp") => {
                port.service_name = Some("ssh".to_string());
                port.service_version = Some("SSH Server".to_string());
            }
            (23, "tcp") => {
                port.service_name = Some("telnet".to_string());
                port.service_version = Some("Telnet Server".to_string());
            }
            (25, "tcp") => {
                port.service_name = Some("smtp".to_string());
                port.service_version = Some("SMTP Server".to_string());
            }
            (53, "tcp") => {
                port.service_name = Some("domain".to_string());
                port.service_version = Some("DNS Server".to_string());
            }
            (80, "tcp") => {
                port.service_name = Some("http".to_string());
                port.service_version = Some("HTTP Server".to_string());
            }
            (110, "tcp") => {
                port.service_name = Some("pop3".to_string());
                port.service_version = Some("POP3 Server".to_string());
            }
            (143, "tcp") => {
                port.service_name = Some("imap".to_string());
                port.service_version = Some("IMAP Server".to_string());
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
            }
            (5432, "tcp") => {
                port.service_name = Some("postgresql".to_string());
                port.service_version = Some("PostgreSQL".to_string());
            }
            (3306, "tcp") => {
                port.service_name = Some("mysql".to_string());
                port.service_version = Some("MySQL".to_string());
            }
            
            // Windows services comuni
            (135, "tcp") => {
                port.service_name = Some("msrpc".to_string());
                port.service_version = Some("Microsoft RPC Endpoint Mapper".to_string());
            }
            (445, "tcp") => {
                port.service_name = Some("microsoft-ds".to_string());
                port.service_version = Some("Microsoft Directory Services".to_string());
            }
            (139, "tcp") => {
                port.service_name = Some("netbios-ssn".to_string());
                port.service_version = Some("NetBIOS Session Service".to_string());
            }
            
            // VMware services
            (902, "tcp") => {
                port.service_name = Some("vmware-authd".to_string());
                port.service_version = Some("VMware Authentication Daemon".to_string());
            }
            (912, "tcp") => {
                port.service_name = Some("vmware-authd".to_string());
                port.service_version = Some("VMware Authentication Daemon".to_string());
            }
            
            // Servizi custom/altri
            (1337, "tcp") => {
                port.service_name = Some("custom-service".to_string());
                port.service_version = Some("Custom Application".to_string());
            }
            
            // Servizi UDP comuni
            (53, "udp") => {
                port.service_name = Some("domain".to_string());
                port.service_version = Some("DNS Server".to_string());
            }
            (67, "udp") => {
                port.service_name = Some("dhcps".to_string());
                port.service_version = Some("DHCP Server".to_string());
            }
            (68, "udp") => {
                port.service_name = Some("dhcpc".to_string());
                port.service_version = Some("DHCP Client".to_string());
            }
            (123, "udp") => {
                port.service_name = Some("ntp".to_string());
                port.service_version = Some("Network Time Protocol".to_string());
            }
            (161, "udp") => {
                port.service_name = Some("snmp".to_string());
                port.service_version = Some("SNMP Agent".to_string());
            }
            
            _ => {
                // Mappatura intelligente per porte non specifiche
                let (service, version) = match (port.port_id, port.protocol.as_str()) {
                    (8000..=8999, "tcp") => ("http-alt", "HTTP Alternative"),
                    (1..=1023, _) => ("system", "System Service"),
                    (1024..=49151, _) => ("registered", "Registered Service"),
                    _ => ("unknown", "Unknown Service"),
                };
                
                port.service_name = Some(service.to_string());
                port.service_version = Some(version.to_string());
            }
        }
    }
    
    (port, vulns)
}

// Analizza le porte aperte e identifica i servizi con enhanced fingerprinting
async fn analyze_open_port(mut port: Port, target: &str, timeout: Duration) -> (Port, Vec<Vulnerability>) {
    let mut vulns = Vec::new();
    
    if port.state == PortState::Open {
        // Determina il servizio dalla porta
        let service_from_port = match port.port_id {
            80 | 8080 => "http",
            443 => "https",
            22 => "ssh",
            21 => "ftp",
            25 => "smtp",
            3306 => "mysql",
            5432 => "postgresql",
            27017 => "mongodb",
            6379 => "redis",
            11211 => "memcached",
            5672 | 15672 => "rabbitmq",
            9200 => "elasticsearch",
            5984 => "couchdb",
            2375 | 2376 => "docker",
            6443 => "kubernetes",
            8443 => "https", // or kubernetes, need context
            2379 | 2380 => "etcd",
            9092 => "kafka",
            1883 | 8883 => "mqtt",
            9042 => "cassandra",
            61616 => "activemq",
            8983 => "solr",
            2181 => "zookeeper",
            8500 => "consul",
            8200 => "vault",
            9000 => "minio",
            _ => "unknown"
        };
        
        // Clone il servizio per evitare problemi di borrowing
        let service = port.service_name.clone().unwrap_or_else(|| service_from_port.to_string());
        
        // ENHANCED FINGERPRINTING: Usa il nuovo sistema per tutti i protocolli
        let banner_ref = port.banner.as_deref();
        if let Some(version) = enhanced_fingerprint(target, port.port_id, &service, banner_ref, timeout).await {
            // Imposta nome servizio se non già impostato
            if port.service_name.is_none() {
                port.service_name = Some(service.clone());
            }
            
            port.service_version = Some(version.clone());
            
            // Calcola confidence score se abbiamo un banner
            if let Some(banner_str) = banner_ref {
                let _confidence = fingerprint::get_version_confidence(banner_str, Some(&version));
            }
        } else if let Some(ref banner) = port.banner {
            // Fallback al metodo standard se enhanced fingerprint non ha funzionato
            if let Some(version) = fingerprint::extract_service_version(&service, banner) {
                if port.service_name.is_none() {
                    port.service_name = Some(service.clone());
                }
                port.service_version = Some(version.clone());
            }
        }
        
        // Rilevamento web application per HTTP/HTTPS
        if let Some(ref banner) = port.banner {
            if service == "http" || service == "https" {
                let web_apps = fingerprint::detect_web_application(banner, None);
                if !web_apps.is_empty() {
                    let apps_str = web_apps.join(", ");
                    let current_version = port.service_version.as_deref().unwrap_or("");
                    port.service_version = Some(format!("{} ({})", current_version, apps_str));
                }
                
                // Estrai versione PHP se presente
                if let Some(php_version) = fingerprint::extract_php_version(banner) {
                    let current_version = port.service_version.as_deref().unwrap_or("");
                    port.service_version = Some(format!("{} + {}", current_version, php_version));
                }
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
                
                // Windows services comuni
                (135, "tcp") => {
                    port.service_name = Some("msrpc".to_string());
                    port.service_version = Some("Microsoft RPC Endpoint Mapper".to_string());
                }
                (445, "tcp") => {
                    port.service_name = Some("microsoft-ds".to_string());
                    port.service_version = Some("Microsoft Directory Services".to_string());
                }
                (139, "tcp") => {
                    port.service_name = Some("netbios-ssn".to_string());
                    port.service_version = Some("NetBIOS Session Service".to_string());
                }
                
                // VMware services
                (902, "tcp") => {
                    port.service_name = Some("vmware-authd".to_string());
                    port.service_version = Some("VMware Authentication Daemon".to_string());
                }
                (912, "tcp") => {
                    port.service_name = Some("vmware-authd".to_string());
                    port.service_version = Some("VMware Authentication Daemon".to_string());
                }
                
                // Servizi custom/altri
                (1337, "tcp") => {
                    port.service_name = Some("custom-service".to_string());
                    port.service_version = Some("Custom Application".to_string());
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
                    // Mappatura intelligente per porte comuni non ancora coperte
                    let (service, version) = match (port.port_id, port.protocol.as_str()) {
                        // Web services aggiuntivi
                        (8000, "tcp") | (8008, "tcp") => ("http-alt", "HTTP Alternative"),
                        (8443, "tcp") => ("https-alt", "HTTPS Alternative"),
                        (8888, "tcp") => ("jupyter", "Jupyter Notebook"),
                        (9000, "tcp") => ("portainer", "Portainer"),
                        (9090, "tcp") => ("websm", "WebSphere Admin"),
                        
                        // Database ports
                        (1521, "tcp") => ("oracle", "Oracle Database"),
                        (1527, "tcp") => ("derby", "Apache Derby"),
                        (1830, "tcp") => ("oracle-net8", "Oracle Net8"),
                        (3050, "tcp") => ("firebird", "Firebird Database"),
                        (5984, "tcp") => ("couchdb", "CouchDB"),
                        (8086, "tcp") => ("influxdb", "InfluxDB"),
                        (9042, "tcp") => ("cassandra", "Cassandra"),
                        (9200, "tcp") => ("elasticsearch", "Elasticsearch"),
                        
                        // Mail services
                        (587, "tcp") => ("smtp-submission", "SMTP Submission"),
                        (465, "tcp") => ("smtps", "SMTP over SSL"),
                        (2525, "tcp") => ("smtp-alt", "SMTP Alternative"),
                        
                        // Remote access
                        (5900, "tcp") => ("vnc", "VNC Remote Desktop"),
                        (5901, "tcp") => ("vnc-1", "VNC Display 1"),
                        (5902, "tcp") => ("vnc-2", "VNC Display 2"),
                        (5985, "tcp") => ("winrm", "Windows Remote Management"),
                        (5986, "tcp") => ("winrm-s", "WinRM over HTTPS"),
                        
                        // Application servers
                        (8080, "tcp") => ("http-proxy", "HTTP Proxy/Tomcat"),
                        (8081, "tcp") => ("http-alt", "HTTP Alternative"),
                        (8090, "tcp") => ("http-alt", "HTTP Alternative"),
                        (9443, "tcp") => ("websphere", "IBM WebSphere"),
                        (7001, "tcp") => ("weblogic", "Oracle WebLogic"),
                        (7002, "tcp") => ("weblogic-ssl", "WebLogic SSL"),
                        
                        // Development/API
                        (3000, "tcp") => ("node", "Node.js App"),
                        (4000, "tcp") => ("dev-server", "Development Server"),
                        (5000, "tcp") => ("flask", "Flask/Development"),
                        (8501, "tcp") => ("streamlit", "Streamlit App"),
                        
                        // Monitoring/Management
                        (2049, "tcp") => ("nfs", "Network File System"),
                        (8140, "tcp") => ("puppet", "Puppet Master"),
                        
                        // Game servers
                        (25565, "tcp") => ("minecraft", "Minecraft Server"),
                        (27015, "tcp") => ("srcds", "Source Game Server"),
                        
                        // IoT/Embedded
                        (1883, "tcp") => ("mqtt", "MQTT Broker"),
                        (8883, "tcp") => ("mqtt-ssl", "MQTT over SSL"),
                        (502, "tcp") => ("modbus", "Modbus"),
                        
                        // High ports patterns
                        (49152..=65535, "tcp") => ("dynamic", "Dynamic/Private"),
                        
                        // UDP services aggiuntivi
                        (123, "udp") => ("ntp", "Network Time Protocol"),
                        (1812, "udp") => ("radius", "RADIUS Authentication"),
                        (1813, "udp") => ("radius-acct", "RADIUS Accounting"),
                        (5060, "udp") => ("sip", "Session Initiation Protocol"),
                        
                        // Se non riconosciuto, usa categoria basata su range
                        (1..=1023, _) => ("system", "System/Well-known"),
                        (1024..=49151, _) => ("registered", "Registered/User"),
                        _ => ("unknown", "Unknown Service"),
                    };
                    
                    port.service_name = Some(service.to_string());
                    port.service_version = Some(version.to_string());
                }
            }
        }
        
        // ========================================
        // POPULATE ENHANCED OUTPUT METADATA
        // ========================================
        
        // 1. Detection Method
        port.detection_method = if port.service_version.as_ref()
            .map(|v| v != "Unknown" && v != "HTTP Server" && v != "HTTPS Server")
            .unwrap_or(false) {
            Some(DetectionMethod::EnhancedProbe)
        } else if port.banner.is_some() {
            Some(DetectionMethod::Banner)
        } else {
            Some(DetectionMethod::PortMapping)
        };
        
        // 2. Service Category
        let service_name = port.service_name.as_deref().unwrap_or("unknown");
        port.service_category = Some(ServiceCategory::from_service(service_name, port.port_id));
        
        // 3. CVE Count
        port.cve_count = Some(vulns.len());
        
        // 4. Full Banner (store untruncated banner)
        port.full_banner = port.banner.clone();
        
        // 5. Risk Level (must be calculated after category and cve_count)
        let has_version = port.service_version.as_ref()
            .map(|v| v != "Unknown" && !v.is_empty())
            .unwrap_or(false);
        
        port.risk_level = Some(RiskLevel::calculate(
            service_name,
            port.port_id,
            port.service_category.as_ref().unwrap(),
            has_version,
            vulns.len()
        ));
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
    // Enhanced CSV header with new metadata columns
    csv.push_str("IP,Hostname,Port,Protocol,State,Service,Version,Banner,Category,RiskLevel,DetectionMethod,CVECount\n");
    
    for host in &scan_results.hosts {
        for port in &host.ports {
            let category = port.service_category.as_ref()
                .map(|c| c.display_name())
                .unwrap_or("Unknown");
            
            let risk_level = port.risk_level.as_ref()
                .map(|r| format!("{:?}", r))
                .unwrap_or_else(|| "Unknown".to_string());
            
            let detection_method = port.detection_method.as_ref()
                .map(|d| d.display_name())
                .unwrap_or("Unknown");
            
            let cve_count = port.cve_count.unwrap_or(0);
            
            csv.push_str(&format!("\"{}\",\"{}\",{},\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",{}\n",
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
                port.banner.as_deref().unwrap_or("").replace("\"", "\\\""),
                category,
                risk_level,
                detection_method,
                cve_count
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
                // Port number (5 chars, right-aligned)
                output.push_str(&format!("   {:>5} ", port.port_id.to_string().bright_green()));
                
                // Protocol (4 chars, left-aligned)
                output.push_str(&format!("{:<4}  ", port.protocol.cyan()));
                
                // Service name (16 chars, left-aligned)
                if let Some(ref service) = port.service_name {
                    output.push_str(&format!("{:<16} ", service.yellow()));
                } else {
                    output.push_str(&format!("{:<16} ", "unknown".dimmed()));
                }
                
                // Service version (28 chars, left-aligned)
                if let Some(ref version) = port.service_version {
                    let version_display = if version.len() > 28 {
                        format!("{}...", &version[..25])
                    } else {
                        version.clone()
                    };
                    output.push_str(&format!("{:<28} ", version_display.white()));
                } else {
                    output.push_str(&format!("{:<28} ", "".dimmed()));
                }
                
                // Banner (truncated to 50 chars, sanitized)
                if let Some(ref banner) = port.banner {
                    // Check if banner contains mostly readable text
                    let alphanumeric_count = banner.chars()
                        .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '.' || *c == '-' || *c == '/')
                        .count();
                    let total_chars = banner.chars().count();
                    let readable_ratio = if total_chars > 0 {
                        alphanumeric_count as f32 / total_chars as f32
                    } else {
                        0.0
                    };
                    
                    // If banner is mostly noise, show [binary data]
                    let display_banner = if readable_ratio < 0.7 || total_chars < 3 {
                        "[binary data]".to_string()
                    } else {
                        // Clean display: keep only reasonable characters
                        let sanitized: String = banner.chars()
                            .filter(|c| c.is_ascii_graphic() || *c == ' ')
                            .collect();
                        
                        if sanitized.len() > 50 {
                            format!("{}...", &sanitized[..47])
                        } else {
                            sanitized
                        }
                    };
                    
                    output.push_str(&format!("{}", display_banner.dimmed()));
                }
                output.push_str("\n");
            }
        }
        
        // Porte filtrate
        if !filtered_ports.is_empty() {
            output.push_str(&format!("\n🟡 FILTERED PORTS: {} ports\n", filtered_ports.len().to_string().yellow()));
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
    
    // Network Discovery Mode (only available with feature flag)
    #[cfg(feature = "network-discovery")]
    if args.network_discovery {
        println!("{}", "🌐 Network Discovery Mode Activated".green().bold());
        
        let mut discovery = NetworkDiscovery::new()
            .with_timeout(Duration::from_millis(args.discovery_timeout))
            .with_concurrency(args.concurrency);
            
        if args.aggressive_discovery {
            discovery = discovery.aggressive();
        }
        
        discovery.include_loopback = args.include_loopback;
        
        let discovery_result = discovery.discover_network().await?;
        
        // Output discovery results
        print_discovery_results(&discovery_result, &args).await?;
        
        if !args.output_format.eq("human") || args.output_file.is_some() {
            save_discovery_results(&discovery_result, &args).await?;
        }
        
        return Ok(());
    }
    
    // Parse targets e porte usando le nuove funzioni
    let targets = parse_targets(&args.target)?;
    
    // Smart port selection has priority over --ports
    let tcp_ports = if let Some(smart_type) = &args.smart_ports {
        match smart_type.to_lowercase().as_str() {
            "windows" => {
                println!("🪟 Using Windows-optimized port selection (~150 ports)");
                get_windows_smart_ports()
            },
            "linux" => {
                println!("🐧 Using Linux-optimized port selection (~120 ports)");
                get_linux_smart_ports()
            },
            "cloud" => {
                println!("☁️  Using Cloud-optimized port selection (~100 ports)");
                get_cloud_smart_ports()
            },
            "iot" => {
                println!("🔌 Using IoT/Embedded-optimized port selection (~80 ports)");
                get_iot_smart_ports()
            },
            _ => {
                eprintln!("⚠️  Unknown smart port type: {}. Valid options: windows, linux, cloud, iot", smart_type);
                eprintln!("Falling back to --ports argument...");
                parse_ports(&args.ports)?
            }
        }
    } else {
        parse_ports(&args.ports)?
    };
    
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
    
    // Informazioni su porte scansionate (nmap-style)
    if args.smart_ports.is_some() {
        // Smart ports already displayed in selection message above
    } else if tcp_ports.len() >= 5000 {
        println!("🔍 TCP Ports: {} (top 5000 common ports - enterprise coverage)", tcp_ports.len().to_string().yellow());
    } else if tcp_ports.len() == get_top_1000_ports().len() {
        println!("🔍 TCP Ports: {} (top 1000 common ports - nmap default)", tcp_ports.len().to_string().yellow());
    } else if tcp_ports.len() == get_top_100_ports().len() {
        println!("🔍 TCP Ports: {} (top 100 common ports)", tcp_ports.len().to_string().yellow());
    } else if tcp_ports.len() == 65535 {
        println!("🔍 TCP Ports: {} (all ports)", tcp_ports.len().to_string().yellow());
    } else {
        println!("🔍 TCP Ports: {} custom ports", tcp_ports.len().to_string().yellow());
    }
    
    if args.udp_scan {
        println!("🔍 UDP Ports: {} ports", udp_ports.len().to_string().yellow());
    }
    
    // Avviso per scan di molte porte (migliorato)
    if tcp_ports.len() >= 65535 {
        println!("⚠️  {}: Full port scan (1-65535) detected!", "WARNING".yellow().bold());
        println!("    This comprehensive scan will take considerable time.");
        println!("💡 {}: Consider using --ports \"top1000\" for faster results", "TIP".cyan().bold());
        println!("    or --timing-template aggressive for faster scanning");
    } else if tcp_ports.len() > 5000 {
        println!("⚠️  {}: Large port range ({} ports) - this may take several minutes.", 
                 "WARNING".yellow().bold(), 
                 tcp_ports.len().to_string().red());
        println!("💡 {}: Use --ports \"top1000\" for faster results or --timing-template aggressive", 
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
                        service_category: None,
                        risk_level: None,
                        detection_method: None,
                        cve_count: None,
                        full_banner: None,
                    }
                } else {
                    // Scansione normale
                    if rate_limit > 0 {
                        tokio::time::sleep(Duration::from_millis(rate_limit)).await;
                    }
                    run_scan_syn(&ip_clone, port, timeout).await
                };
                
                pb_clone.inc(1);
                
                if result.state == PortState::Open {
                    if service_scan {
                        analyze_open_port(result, &ip_clone, timeout).await
                    } else {
                        // Mappatura base servizi anche senza service_scan
                        let (mut port, vulns) = map_basic_service(result).await;
                        // Non fare banner grabbing se service_scan è false
                        port.banner = None;
                        (port, vulns)
                    }
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
                        analyze_open_port(result, &ip_clone, timeout).await
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

    // Serialization (Human, JSON, YAML, XML, CSV, MD, HTML)
    let output = match args.output_format.as_str() {
        "json" => serde_json::to_string_pretty(&scan_results)?,
        "yaml" => serde_yaml::to_string(&scan_results)?,
        "xml" => generate_xml_output(&scan_results),
        "csv" => generate_csv_output(&scan_results),
        "md" | "markdown" => generate_markdown_output(&scan_results),
        "html" => output::generate_html_report(&scan_results),
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

// Network Discovery Output Functions (only compiled with feature flag)
#[cfg(feature = "network-discovery")]
async fn print_discovery_results(result: &NetworkDiscoveryResult, _args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n{}", "🌐 NETWORK DISCOVERY RESULTS".green().bold());
    println!("{}", "═".repeat(50).bright_black());

    // Summary
    println!("📊 {}: {} hosts discovered in {}ms", 
             "Summary".cyan().bold(), 
             result.discovered_hosts.len().to_string().green(), 
             result.scan_duration.to_string().yellow());

    // Network interfaces
    println!("\n📡 {} ({} interfaces):", "Network Interfaces".cyan().bold(), result.network_interfaces.len());
    for interface in &result.network_interfaces {
        let status = if interface.is_up { "UP".green() } else { "DOWN".red() };
        let loopback = if interface.is_loopback { " [LOOPBACK]".bright_black() } else { "".bright_black() };
        
        println!("   {} {} - {} {}{}",
                 "•".bright_blue(),
                 interface.name.bright_white(),
                 interface.ip_address.to_string().yellow(),
                 status,
                 loopback);
        
        if let Some(mac) = &interface.mac_address {
            println!("     MAC: {}", mac.bright_black());
        }
    }

    // Network ranges
    println!("\n🌐 {} ({} ranges):", "Network Ranges".cyan().bold(), result.network_ranges.len());
    for range in &result.network_ranges {
        println!("   {} {}", "•".bright_blue(), range.yellow());
    }

    // Gateway and DNS
    if let Some(gateway) = result.gateway {
        println!("\n🚪 {}: {}", "Default Gateway".cyan().bold(), gateway.to_string().green());
    }

    if !result.dns_servers.is_empty() {
        println!("\n🔍 {} ({} servers):", "DNS Servers".cyan().bold(), result.dns_servers.len());
        for dns in &result.dns_servers {
            println!("   {} {}", "•".bright_blue(), dns.to_string().yellow());
        }
    }

    // Discovery methods used
    println!("\n🔧 {}: {}", "Discovery Methods".cyan().bold(), result.discovery_methods_used.join(", ").bright_white());

    // Discovered hosts
    if result.discovered_hosts.is_empty() {
        println!("\n❌ No hosts discovered");
        return Ok(());
    }

    println!("\n👥 {} ({} hosts):", "Discovered Hosts".cyan().bold(), result.discovered_hosts.len());
    println!("{}", "─".repeat(80).bright_black());

    for (i, host) in result.discovered_hosts.iter().enumerate() {
        let host_num = format!("[{}]", i + 1).bright_black();
        let ip = host.ip_address.to_string().bright_white();
        let gateway_marker = if host.is_gateway { " 🚪" } else { "" };

        println!("\n{} {}{}", host_num, ip, gateway_marker);

        // MAC Address and Vendor
        if let Some(mac) = &host.mac_address {
            let vendor_info = if let Some(vendor) = &host.vendor {
                format!(" ({})", vendor.green())
            } else if let Some(vendor) = get_mac_vendor(mac) {
                format!(" ({})", vendor.green())
            } else {
                String::new()
            };
            println!("   MAC: {}{}", mac.bright_cyan(), vendor_info);
        }

        // Hostname
        if let Some(hostname) = &host.hostname {
            println!("   Hostname: {}", hostname.bright_green());
        }

        // Response time
        if let Some(response_time) = host.response_time {
            println!("   Response Time: {}ms", response_time.to_string().yellow());
        }

        // Discovery method
        println!("   Discovery: {}", host.discovery_method.bright_blue());

        // Port hints
        if !host.ports_hint.is_empty() {
            let ports_str: Vec<String> = host.ports_hint.iter().map(|p| p.to_string()).collect();
            println!("   Common Ports: {}", ports_str.join(", ").bright_magenta());
        }
    }

    println!("\n{}", "═".repeat(50).bright_black());
    println!("✅ Network discovery completed successfully");

    Ok(())
}

#[cfg(feature = "network-discovery")]
async fn save_discovery_results(result: &NetworkDiscoveryResult, args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let output = match args.output_format.as_str() {
        "json" => serde_json::to_string_pretty(result)?,
        "yaml" => serde_yaml::to_string(result)?,
        "xml" => generate_discovery_xml_output(result),
        "csv" => generate_discovery_csv_output(result),
        "md" | "markdown" => generate_discovery_markdown_output(result),
        "human" | _ => generate_discovery_human_output(result),
    };

    if let Some(filename) = &args.output_file {
        tokio::fs::write(filename, &output).await?;
        println!("💾 Discovery results saved to: {}", filename.green());
    }

    Ok(())
}

#[cfg(feature = "network-discovery")]
fn generate_discovery_xml_output(result: &NetworkDiscoveryResult) -> String {
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<nextmap_network_discovery>\n");
    xml.push_str(&format!("  <summary>\n"));
    xml.push_str(&format!("    <hosts_discovered>{}</hosts_discovered>\n", result.discovered_hosts.len()));
    xml.push_str(&format!("    <scan_duration_ms>{}</scan_duration_ms>\n", result.scan_duration));
    xml.push_str(&format!("  </summary>\n"));

    if let Some(gateway) = result.gateway {
        xml.push_str(&format!("  <gateway>{}</gateway>\n", gateway));
    }

    xml.push_str("  <discovered_hosts>\n");
    for host in &result.discovered_hosts {
        xml.push_str("    <host>\n");
        xml.push_str(&format!("      <ip_address>{}</ip_address>\n", host.ip_address));
        if let Some(mac) = &host.mac_address {
            xml.push_str(&format!("      <mac_address>{}</mac_address>\n", mac));
        }
        if let Some(hostname) = &host.hostname {
            xml.push_str(&format!("      <hostname>{}</hostname>\n", hostname));
        }
        if let Some(response_time) = host.response_time {
            xml.push_str(&format!("      <response_time_ms>{}</response_time_ms>\n", response_time));
        }
        xml.push_str(&format!("      <discovery_method>{}</discovery_method>\n", host.discovery_method));
        xml.push_str(&format!("      <is_gateway>{}</is_gateway>\n", host.is_gateway));
        xml.push_str("    </host>\n");
    }
    xml.push_str("  </discovered_hosts>\n");
    xml.push_str("</nextmap_network_discovery>\n");
    xml
}

#[cfg(feature = "network-discovery")]
fn generate_discovery_csv_output(result: &NetworkDiscoveryResult) -> String {
    let mut csv = String::new();
    csv.push_str("IP Address,MAC Address,Hostname,Response Time (ms),Discovery Method,Is Gateway,Vendor\n");

    for host in &result.discovered_hosts {
        let mac_str = host.mac_address.as_deref().unwrap_or("");
        let hostname_str = host.hostname.as_deref().unwrap_or("");
        let response_time_str = host.response_time.map_or(String::new(), |t| t.to_string());
        let vendor_str = host.vendor.as_deref().unwrap_or("");

        csv.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            host.ip_address,
            mac_str,
            hostname_str,
            response_time_str,
            host.discovery_method,
            host.is_gateway,
            vendor_str
        ));
    }

    csv
}

#[cfg(feature = "network-discovery")]
fn generate_discovery_markdown_output(result: &NetworkDiscoveryResult) -> String {
    let mut md = String::new();
    md.push_str("# NextMap Network Discovery Report\n\n");

    // Summary
    md.push_str("## Summary\n\n");
    md.push_str(&format!("- **Hosts Discovered**: {}\n", result.discovered_hosts.len()));
    md.push_str(&format!("- **Scan Duration**: {}ms\n", result.scan_duration));
    md.push_str(&format!("- **Discovery Methods**: {}\n", result.discovery_methods_used.join(", ")));

    if let Some(gateway) = result.gateway {
        md.push_str(&format!("- **Default Gateway**: {}\n", gateway));
    }

    md.push_str("\n");

    // Network Interfaces
    md.push_str("## Network Interfaces\n\n");
    md.push_str("| Interface | IP Address | MAC Address | Status |\n");
    md.push_str("|-----------|------------|-------------|--------|\n");

    for interface in &result.network_interfaces {
        let mac_str = interface.mac_address.as_deref().unwrap_or("-");
        let status = if interface.is_up { "UP" } else { "DOWN" };
        md.push_str(&format!("| {} | {} | {} | {} |\n", 
                            interface.name, interface.ip_address, mac_str, status));
    }

    md.push_str("\n");

    // Discovered Hosts
    if !result.discovered_hosts.is_empty() {
        md.push_str("## Discovered Hosts\n\n");
        md.push_str("| IP Address | MAC Address | Hostname | Response Time | Discovery Method | Gateway |\n");
        md.push_str("|------------|-------------|----------|---------------|------------------|----------|\n");

        for host in &result.discovered_hosts {
            let mac_str = host.mac_address.as_deref().unwrap_or("-");
            let hostname_str = host.hostname.as_deref().unwrap_or("-");
            let response_time_str = host.response_time.map_or("-".to_string(), |t| format!("{}ms", t));
            let gateway_str = if host.is_gateway { "Yes" } else { "No" };

            md.push_str(&format!("| {} | {} | {} | {} | {} | {} |\n",
                                host.ip_address,
                                mac_str,
                                hostname_str,
                                response_time_str,
                                host.discovery_method,
                                gateway_str));
        }
    }

    md.push_str("\n---\n");
    md.push_str(&format!("*Generated by NextMap v{} on {}*\n", 
                        env!("CARGO_PKG_VERSION"), 
                        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));

    md
}

#[cfg(feature = "network-discovery")]
fn generate_discovery_human_output(result: &NetworkDiscoveryResult) -> String {
    let mut output = String::new();
    
    output.push_str("🌐 NETWORK DISCOVERY REPORT\n");
    output.push_str("═══════════════════════════\n\n");

    output.push_str(&format!("📊 Summary: {} hosts discovered in {}ms\n", 
                            result.discovered_hosts.len(), result.scan_duration));
    
    if let Some(gateway) = result.gateway {
        output.push_str(&format!("🚪 Default Gateway: {}\n", gateway));
    }

    output.push_str(&format!("🔧 Discovery Methods: {}\n\n", result.discovery_methods_used.join(", ")));

    if !result.discovered_hosts.is_empty() {
        output.push_str(&format!("👥 Discovered Hosts ({}):\n", result.discovered_hosts.len()));
        output.push_str(&"─".repeat(50));
        output.push('\n');

        for (i, host) in result.discovered_hosts.iter().enumerate() {
            output.push_str(&format!("\n[{}] {}\n", i + 1, host.ip_address));
            
            if let Some(mac) = &host.mac_address {
                let vendor_info = if let Some(vendor) = &host.vendor {
                    format!(" ({})", vendor)
                } else if let Some(vendor) = get_mac_vendor(mac) {
                    format!(" ({})", vendor)
                } else {
                    String::new()
                };
                output.push_str(&format!("   MAC: {}{}\n", mac, vendor_info));
            }

            if let Some(hostname) = &host.hostname {
                output.push_str(&format!("   Hostname: {}\n", hostname));
            }

            if let Some(response_time) = host.response_time {
                output.push_str(&format!("   Response Time: {}ms\n", response_time));
            }

            output.push_str(&format!("   Discovery: {}\n", host.discovery_method));

            if host.is_gateway {
                output.push_str("   🚪 Gateway device\n");
            }
        }
    }

    output.push_str("\n═══════════════════════════\n");
    output.push_str("✅ Network discovery completed\n");

    output
}