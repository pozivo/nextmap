// src/probes.rs - Multi-Level Service Probing System
// Inspired by Nmap's nmap-service-probes

use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use std::time::Duration;
use regex::Regex;

/// Service probe definition
#[derive(Debug, Clone)]
pub struct ServiceProbe {
    pub name: &'static str,
    pub data: &'static [u8],
    pub ports: &'static [u16],  // Empty slice = apply to all ports
}

/// Match signature for service identification
#[derive(Debug, Clone)]
pub struct ServiceMatch {
    pub probe_name: &'static str,
    pub service: &'static str,
    pub pattern: &'static str,
    pub version_extract: Option<&'static str>,
}

/// Result of a probe attempt
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub probe_name: String,
    pub response: String,
    pub service_identified: Option<String>,
    pub version: Option<String>,
    pub confidence: u8,  // 0-100
}

// === PROBE DEFINITIONS ===
// Ordered by success rate and speed

// Port arrays (static slices)
const ALL_PORTS: &[u16] = &[];  // Empty = all ports
const HTTP_PORTS: &[u16] = &[80, 443, 8000, 8080, 8443, 8888, 9000, 9200, 5984];
const HTTP_COMMON: &[u16] = &[80, 443, 8000, 8080, 8443];
const MAIL_PORTS: &[u16] = &[21, 25, 110, 143];
const SSL_PORTS: &[u16] = &[443, 465, 563, 585, 636, 989, 990, 992, 993, 994, 995, 8443];
const FTP_PORTS: &[u16] = &[21];
const SMTP_PORTS: &[u16] = &[25, 465, 587];
const POP3_PORTS: &[u16] = &[110, 995];
const IMAP_PORTS: &[u16] = &[143, 993];
const MYSQL_PORTS: &[u16] = &[3306];
const PGSQL_PORTS: &[u16] = &[5432];
const REDIS_PORTS: &[u16] = &[6379];
const MEMCACHED_PORTS: &[u16] = &[11211];
const MONGODB_PORTS: &[u16] = &[27017, 27018, 27019];
const ELASTICSEARCH_PORTS: &[u16] = &[9200, 9300];
const RTSP_PORTS: &[u16] = &[554, 8554];
const SIP_PORTS: &[u16] = &[5060, 5061];
const RDP_PORTS: &[u16] = &[3389];
const VNC_PORTS: &[u16] = &[5900, 5901, 5902];
const ZOOKEEPER_PORTS: &[u16] = &[2181];
const KAFKA_PORTS: &[u16] = &[9092];
const DOCKER_PORTS: &[u16] = &[2375, 2376];
const K8S_PORTS: &[u16] = &[6443, 8443, 10250];

pub const PROBES: &[ServiceProbe] = &[
    // NULL probe - just read banner
    ServiceProbe {
        name: "NULL",
        data: b"",
        ports: ALL_PORTS,
    },
    
    // Generic newlines - triggers many services
    ServiceProbe {
        name: "GenericLines",
        data: b"\r\n\r\n",
        ports: ALL_PORTS,
    },
    
    // HTTP GET request
    ServiceProbe {
        name: "GetRequest",
        data: b"GET / HTTP/1.0\r\n\r\n",
        ports: HTTP_PORTS,
    },
    
    // HTTP OPTIONS
    ServiceProbe {
        name: "HTTPOptions",
        data: b"OPTIONS / HTTP/1.0\r\n\r\n",
        ports: HTTP_COMMON,
    },
    
    // HELP command (works on many text protocols)
    ServiceProbe {
        name: "Help",
        data: b"HELP\r\n",
        ports: ALL_PORTS,
    },
    
    // QUIT command
    ServiceProbe {
        name: "Quit",
        data: b"QUIT\r\n",
        ports: MAIL_PORTS,
    },
    
    // SSL/TLS ClientHello
    ServiceProbe {
        name: "SSLSessionReq",
        data: b"\x16\x03\x00\x00\x5f\x01\x00\x00\x5b\x03\x03",
        ports: SSL_PORTS,
    },
    
    // FTP HELP
    ServiceProbe {
        name: "FTPHelp",
        data: b"HELP\r\n",
        ports: FTP_PORTS,
    },
    
    // SMTP HELO
    ServiceProbe {
        name: "SMTPHelo",
        data: b"HELO example.com\r\n",
        ports: SMTP_PORTS,
    },
    
    // POP3 capabilities
    ServiceProbe {
        name: "POP3Capabilities",
        data: b"CAPA\r\n",
        ports: POP3_PORTS,
    },
    
    // IMAP capabilities
    ServiceProbe {
        name: "IMAPCapabilities",
        data: b"A001 CAPABILITY\r\n",
        ports: IMAP_PORTS,
    },
    
    // MySQL greeting (wait for server banner)
    ServiceProbe {
        name: "MySQLGreeting",
        data: b"",
        ports: MYSQL_PORTS,
    },
    
    // PostgreSQL startup
    ServiceProbe {
        name: "PostgreSQLStartup",
        data: b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
        ports: PGSQL_PORTS,
    },
    
    // Redis INFO
    ServiceProbe {
        name: "RedisInfo",
        data: b"INFO\r\n",
        ports: REDIS_PORTS,
    },
    
    // Memcached version
    ServiceProbe {
        name: "MemcachedVersion",
        data: b"version\r\n",
        ports: MEMCACHED_PORTS,
    },
    
    // MongoDB hello
    ServiceProbe {
        name: "MongoDBHello",
        data: b"{ \"hello\": 1 }\r\n",
        ports: MONGODB_PORTS,
    },
    
    // Elasticsearch cluster info
    ServiceProbe {
        name: "ElasticsearchCluster",
        data: b"GET /_cluster/health HTTP/1.0\r\n\r\n",
        ports: ELASTICSEARCH_PORTS,
    },
    
    // RTSP OPTIONS
    ServiceProbe {
        name: "RTSPRequest",
        data: b"OPTIONS / RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        ports: RTSP_PORTS,
    },
    
    // SIP OPTIONS
    ServiceProbe {
        name: "SIPOptions",
        data: b"OPTIONS sip:nm@example.com SIP/2.0\r\n\r\n",
        ports: SIP_PORTS,
    },
    
    // RDP (Remote Desktop) initial
    ServiceProbe {
        name: "RDPInitial",
        data: b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00",
        ports: RDP_PORTS,
    },
    
    // VNC RFB
    ServiceProbe {
        name: "VNCHandshake",
        data: b"",
        ports: VNC_PORTS,
    },
    
    // Zookeeper stat
    ServiceProbe {
        name: "ZookeeperStat",
        data: b"stat\n",
        ports: ZOOKEEPER_PORTS,
    },
    
    // Kafka metadata request (simplified)
    ServiceProbe {
        name: "KafkaMetadata",
        data: b"\x00\x00\x00\x00",
        ports: KAFKA_PORTS,
    },
    
    // Docker API
    ServiceProbe {
        name: "DockerVersion",
        data: b"GET /version HTTP/1.0\r\n\r\n",
        ports: DOCKER_PORTS,
    },
    
    // Kubernetes API
    ServiceProbe {
        name: "KubernetesVersion",
        data: b"GET /version HTTP/1.0\r\n\r\n",
        ports: K8S_PORTS,
    },
];

// === SERVICE MATCH SIGNATURES ===

pub const SERVICE_MATCHES: &[ServiceMatch] = &[
    // SSH signatures
    ServiceMatch {
        probe_name: "NULL",
        service: "ssh",
        pattern: r"^SSH-[\d\.]+-OpenSSH_([\d\.p]+)",
        version_extract: Some(r"OpenSSH $1"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ssh",
        pattern: r"^SSH-([\d\.]+)-",
        version_extract: Some(r"SSH $1"),
    },
    
    // HTTP signatures
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"HTTP/1\.[01] \d+ ",
        version_extract: None,
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: nginx/([\d\.]+)",
        version_extract: Some(r"nginx $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Apache/([\d\.]+)",
        version_extract: Some(r"Apache $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Microsoft-IIS/([\d\.]+)",
        version_extract: Some(r"IIS $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: lighttpd/([\d\.]+)",
        version_extract: Some(r"lighttpd $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Caddy/([\d\.]+)",
        version_extract: Some(r"Caddy $1"),
    },
    
    // FTP signatures
    ServiceMatch {
        probe_name: "NULL",
        service: "ftp",
        pattern: r"^220.*FTP",
        version_extract: None,
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ftp",
        pattern: r"220.*ProFTPD ([\d\.]+)",
        version_extract: Some(r"ProFTPD $1"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ftp",
        pattern: r"220.*vsftpd ([\d\.]+)",
        version_extract: Some(r"vsftpd $1"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ftp",
        pattern: r"220.*FileZilla Server ([\d\.]+)",
        version_extract: Some(r"FileZilla $1"),
    },
    
    // SMTP signatures
    ServiceMatch {
        probe_name: "NULL",
        service: "smtp",
        pattern: r"^220.*SMTP",
        version_extract: None,
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "smtp",
        pattern: r"220.*Postfix",
        version_extract: Some(r"Postfix"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "smtp",
        pattern: r"220.*Exim ([\d\.]+)",
        version_extract: Some(r"Exim $1"),
    },
    ServiceMatch {
        probe_name: "SMTPHelo",
        service: "smtp",
        pattern: r"250.*ESMTP",
        version_extract: None,
    },
    
    // MySQL signatures
    ServiceMatch {
        probe_name: "MySQLGreeting",
        service: "mysql",
        pattern: r"\x00\x00\x00\x0a([\d\.]+)",
        version_extract: Some(r"MySQL $1"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "mysql",
        pattern: r"mysql_native_password",
        version_extract: Some(r"MySQL"),
    },
    
    // PostgreSQL signatures
    ServiceMatch {
        probe_name: "PostgreSQLStartup",
        service: "postgresql",
        pattern: r"FATAL",
        version_extract: Some(r"PostgreSQL"),
    },
    
    // Redis signatures
    ServiceMatch {
        probe_name: "RedisInfo",
        service: "redis",
        pattern: r"redis_version:([\d\.]+)",
        version_extract: Some(r"Redis $1"),
    },
    ServiceMatch {
        probe_name: "RedisInfo",
        service: "redis",
        pattern: r"\$\d+\r\n#",
        version_extract: Some(r"Redis"),
    },
    
    // Memcached signatures
    ServiceMatch {
        probe_name: "MemcachedVersion",
        service: "memcached",
        pattern: r"VERSION ([\d\.]+)",
        version_extract: Some(r"Memcached $1"),
    },
    
    // Elasticsearch signatures
    ServiceMatch {
        probe_name: "GetRequest",
        service: "elasticsearch",
        pattern: r#""name"\s*:\s*"[^"]+",\s*"cluster_name""#,
        version_extract: None,
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "elasticsearch",
        pattern: r#""version"\s*:\s*\{\s*"number"\s*:\s*"([\d\.]+)""#,
        version_extract: Some(r"Elasticsearch $1"),
    },
    
    // Docker signatures
    ServiceMatch {
        probe_name: "DockerVersion",
        service: "docker",
        pattern: r#""Version":"([\d\.]+)""#,
        version_extract: Some(r"Docker $1"),
    },
    
    // MongoDB signatures  
    ServiceMatch {
        probe_name: "MongoDBHello",
        service: "mongodb",
        pattern: r#""ok"\s*:\s*1"#,
        version_extract: Some(r"MongoDB"),
    },
    
    // POP3 signatures
    ServiceMatch {
        probe_name: "NULL",
        service: "pop3",
        pattern: r"^\+OK",
        version_extract: None,
    },
    ServiceMatch {
        probe_name: "POP3Capabilities",
        service: "pop3",
        pattern: r"^\+OK",
        version_extract: None,
    },
    
    // IMAP signatures
    ServiceMatch {
        probe_name: "NULL",
        service: "imap",
        pattern: r"\* OK.*IMAP",
        version_extract: None,
    },
    ServiceMatch {
        probe_name: "IMAPCapabilities",
        service: "imap",
        pattern: r"\* CAPABILITY",
        version_extract: None,
    },
    
    // VNC signatures
    ServiceMatch {
        probe_name: "VNCHandshake",
        service: "vnc",
        pattern: r"^RFB \d{3}\.\d{3}",
        version_extract: None,
    },
    
    // RDP signatures
    ServiceMatch {
        probe_name: "RDPInitial",
        service: "ms-wbt-server",
        pattern: r"\x03\x00\x00",
        version_extract: Some(r"RDP"),
    },
    
    // Zookeeper signatures
    ServiceMatch {
        probe_name: "ZookeeperStat",
        service: "zookeeper",
        pattern: r"Zookeeper version: ([\d\.\-\w]+)",
        version_extract: Some(r"Zookeeper $1"),
    },
];

/// Execute probes against a target port
pub async fn probe_service(
    target: &str,
    port: u16,
    timeout: Duration,
) -> Option<ProbeResult> {
    // Filter applicable probes for this port
    let applicable_probes: Vec<&ServiceProbe> = PROBES
        .iter()
        .filter(|probe| {
            // Empty ports array = apply to all ports
            probe.ports.is_empty() || probe.ports.contains(&port)
        })
        .collect();

    // Try each probe in order
    for probe in applicable_probes {
        if let Some(result) = try_probe(target, port, probe, timeout).await {
            // Try to match response against service signatures
            if let Some(matched) = match_response(&result.response, probe.name) {
                return Some(ProbeResult {
                    probe_name: probe.name.to_string(),
                    response: result.response,
                    service_identified: Some(matched.0),
                    version: matched.1,
                    confidence: matched.2,
                });
            }
            
            // Even if no match, return the response
            return Some(result);
        }
    }

    None
}

/// Try a single probe
async fn try_probe(
    target: &str,
    port: u16,
    probe: &ServiceProbe,
    timeout: Duration,
) -> Option<ProbeResult> {
    let socket_addr = format!("{}:{}", target, port);
    
    match tokio::time::timeout(timeout, TcpStream::connect(&socket_addr)).await {
        Ok(Ok(mut stream)) => {
            // Send probe data if not empty
            if !probe.data.is_empty() {
                if stream.write_all(probe.data).await.is_err() {
                    return None;
                }
            }
            
            // Read response
            let mut buffer = vec![0u8; 8192];
            match tokio::time::timeout(timeout, stream.read(&mut buffer)).await {
                Ok(Ok(n)) if n > 0 => {
                    let response = String::from_utf8_lossy(&buffer[..n]).to_string();
                    Some(ProbeResult {
                        probe_name: probe.name.to_string(),
                        response,
                        service_identified: None,
                        version: None,
                        confidence: 0,
                    })
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Match response against service signatures
fn match_response(response: &str, probe_name: &str) -> Option<(String, Option<String>, u8)> {
    for sig in SERVICE_MATCHES {
        if sig.probe_name != probe_name {
            continue;
        }
        
        if let Ok(re) = Regex::new(sig.pattern) {
            if let Some(captures) = re.captures(response) {
                let version = if let Some(template) = sig.version_extract {
                    // Extract version using capture groups
                    let mut version_str = template.to_string();
                    for (i, cap) in captures.iter().enumerate() {
                        if let Some(m) = cap {
                            version_str = version_str.replace(&format!("${}", i), m.as_str());
                        }
                    }
                    Some(version_str)
                } else {
                    None
                };
                
                // Calculate confidence based on probe type
                let confidence = match probe_name {
                    "NULL" => 90,  // High confidence for banner-based
                    "GetRequest" => 85,
                    "GenericLines" => 70,
                    _ => 75,
                };
                
                return Some((sig.service.to_string(), version, confidence));
            }
        }
    }
    
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_definitions() {
        assert!(!PROBES.is_empty());
        assert!(!SERVICE_MATCHES.is_empty());
    }

    #[test]
    fn test_match_ssh_banner() {
        let response = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5";
        let result = match_response(response, "NULL");
        assert!(result.is_some());
        let (service, version, confidence) = result.unwrap();
        assert_eq!(service, "ssh");
        assert!(version.is_some());
        assert!(confidence >= 80);
    }

    #[test]
    fn test_match_http_nginx() {
        let response = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n";
        let result = match_response(response, "GetRequest");
        assert!(result.is_some());
        let (service, version, _) = result.unwrap();
        assert_eq!(service, "http");
        assert!(version.unwrap().contains("nginx"));
    }

    #[test]
    fn test_match_redis() {
        let response = "$3625\r\n# Server\r\nredis_version:6.2.6\r\n";
        let result = match_response(response, "RedisInfo");
        assert!(result.is_some());
        let (service, version, _) = result.unwrap();
        assert_eq!(service, "redis");
        assert!(version.unwrap().contains("6.2.6"));
    }
}
