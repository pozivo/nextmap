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
    
    // HTTP GET request with Host header (modern servers require this)
    ServiceProbe {
        name: "GetRequest",
        data: b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
        ports: HTTP_PORTS,
    },
    
    // HTTP OPTIONS
    ServiceProbe {
        name: "HTTPOptions",
        data: b"OPTIONS / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        ports: HTTP_COMMON,
    },
    
    // HTTP HEAD request for server identification
    ServiceProbe {
        name: "HTTPHead",
        data: b"HEAD / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
        ports: HTTP_COMMON,
    },
    
    // HTTP with more headers to trigger verbose responses
    ServiceProbe {
        name: "HTTPVerbose",
        data: b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\n\r\n",
        ports: HTTP_COMMON,
    },
    
    // HTTP GET for common paths that reveal technology
    ServiceProbe {
        name: "HTTPRobots",
        data: b"GET /robots.txt HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
        ports: HTTP_COMMON,
    },
    
    // HTTP GET for server status (Apache/nginx)
    ServiceProbe {
        name: "HTTPServerStatus",
        data: b"GET /server-status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        ports: HTTP_COMMON,
    },
    
    // HTTP TRACE method (some servers reveal info)
    ServiceProbe {
        name: "HTTPTrace",
        data: b"TRACE / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
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
// Expanded database: 150+ signatures for maximum detection accuracy
// NextMap is a direct Nmap competitor - no external dependencies needed!

pub const SERVICE_MATCHES: &[ServiceMatch] = &[
    // ============ SSH SIGNATURES (15) ============
    ServiceMatch {
        probe_name: "NULL",
        service: "ssh",
        pattern: r"^SSH-[\d\.]+-OpenSSH_([\d\.p]+)",
        version_extract: Some(r"OpenSSH $1"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ssh",
        pattern: r"^SSH-[\d\.]+-OpenSSH_([\d\.p]+)\s+Debian",
        version_extract: Some(r"OpenSSH $1 Debian"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ssh",
        pattern: r"^SSH-[\d\.]+-OpenSSH_([\d\.p]+)\s+Ubuntu",
        version_extract: Some(r"OpenSSH $1 Ubuntu"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ssh",
        pattern: r"^SSH-[\d\.]+-OpenSSH_([\d\.p]+)\s+FreeBSD",
        version_extract: Some(r"OpenSSH $1 FreeBSD"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ssh",
        pattern: r"^SSH-([\d\.]+)-Dropbear_([\d\.]+)",
        version_extract: Some(r"Dropbear SSH $2"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ssh",
        pattern: r"^SSH-[\d\.]+-libssh_([\d\.]+)",
        version_extract: Some(r"libssh $1"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ssh",
        pattern: r"^SSH-[\d\.]+-OpenSSH_for_Windows_([\d\.]+)",
        version_extract: Some(r"OpenSSH for Windows $1"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ssh",
        pattern: r"^SSH-[\d\.]+-Cisco-([\d\.]+)",
        version_extract: Some(r"Cisco SSH $1"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ssh",
        pattern: r"^SSH-[\d\.]+-Sun_SSH_([\d\.]+)",
        version_extract: Some(r"Sun SSH $1"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ssh",
        pattern: r"^SSH-[\d\.]+-RomSShell_([\d\.]+)",
        version_extract: Some(r"RomSShell $1"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ssh",
        pattern: r"^SSH-[\d\.]+-ROSSSH",
        version_extract: Some(r"MikroTik RouterOS SSH"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ssh",
        pattern: r"^SSH-[\d\.]+-mod_sftp/([\d\.]+)",
        version_extract: Some(r"mod_sftp $1"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ssh",
        pattern: r"^SSH-[\d\.]+-WeOnlyDo",
        version_extract: Some(r"WeOnlyDo SSH Server"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ssh",
        pattern: r"^SSH-[\d\.]+-Maverick_SSHD",
        version_extract: Some(r"Maverick SSHD"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ssh",
        pattern: r"^SSH-([\d\.]+)-",
        version_extract: Some(r"SSH $1"),
    },
    
    // ============ HTTP/HTTPS SIGNATURES (60+) ============
    // High-specificity patterns for servers that hide their identity
    
    // Generic HTTP detection - Nmap-style clear descriptions
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"(?i)^HTTP/1\.1 \d{3} ",
        version_extract: Some(r"HTTP/1.1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"(?i)^HTTP/1\.0 \d{3} ",
        version_extract: Some(r"HTTP/1.0"),
    },
    ServiceMatch {
        probe_name: "HTTPHead",
        service: "http",
        pattern: r"(?i)^HTTP/1\.[01] \d{3} ",
        version_extract: Some(r"HTTP/1.x"),
    },
    ServiceMatch {
        probe_name: "HTTPVerbose",
        service: "http",
        pattern: r"(?i)^HTTP/1\.[01] \d{3} ",
        version_extract: Some(r"HTTP/1.x"),
    },
    
    // Detect HTTP by common headers when Server header is missing
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"(?i)Content-Type:\s*text/html",
        version_extract: Some(r"HTML document"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"(?i)Content-Type:\s*application/json",
        version_extract: Some(r"HTTP API (JSON)"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"(?i)Connection:\s*(keep-alive|close)",
        version_extract: None,  // Too generic, use only as last resort
    },
    
    // nginx variants - try version first, then fallback to generic
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: nginx/([\d\.]+)",
        version_extract: Some(r"nginx $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: nginx(?:/[\d\.]+)?\s*\(Ubuntu\)",
        version_extract: Some(r"nginx (Ubuntu)"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: nginx(?:/[\d\.]+)?\s*\(Debian\)",
        version_extract: Some(r"nginx (Debian)"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"(?i)Server:\s*nginx\s*(?:\r|\n|$)",
        version_extract: Some(r"nginx (version hidden)"),
    },
    ServiceMatch {
        probe_name: "HTTPHead",
        service: "http",
        pattern: r"Server: nginx/([\d\.]+)",
        version_extract: Some(r"nginx $1"),
    },
    ServiceMatch {
        probe_name: "HTTPHead",
        service: "http",
        pattern: r"(?i)Server:\s*nginx\s*(?:\r|\n|$)",
        version_extract: Some(r"nginx (version hidden)"),
    },
    // Apache variants
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Apache/([\d\.]+)",
        version_extract: Some(r"Apache $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Apache/([\d\.]+) \(Debian\)",
        version_extract: Some(r"Apache $1 Debian"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Apache/([\d\.]+) \(Ubuntu\)",
        version_extract: Some(r"Apache $1 Ubuntu"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Apache/([\d\.]+) \(Red Hat\)",
        version_extract: Some(r"Apache $1 Red Hat"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Apache/([\d\.]+) \(CentOS\)",
        version_extract: Some(r"Apache $1 CentOS"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Apache/([\d\.]+) \(Win32\)",
        version_extract: Some(r"Apache $1 Windows"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Apache/([\d\.]+) \(Win64\)",
        version_extract: Some(r"Apache $1 Windows 64-bit"),
    },
    // IIS variants
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Microsoft-IIS/([\d\.]+)",
        version_extract: Some(r"IIS $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Microsoft-IIS/10\.0",
        version_extract: Some(r"IIS 10.0 (Windows Server 2016/2019)"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Microsoft-IIS/8\.5",
        version_extract: Some(r"IIS 8.5 (Windows Server 2012 R2)"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Microsoft-IIS/8\.0",
        version_extract: Some(r"IIS 8.0 (Windows Server 2012)"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Microsoft-IIS/7\.5",
        version_extract: Some(r"IIS 7.5 (Windows Server 2008 R2)"),
    },
    // Other web servers
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
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Caddy",
        version_extract: Some(r"Caddy"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: LiteSpeed/([\d\.]+)",
        version_extract: Some(r"LiteSpeed $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: OpenLiteSpeed/([\d\.]+)",
        version_extract: Some(r"OpenLiteSpeed $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Cherokee/([\d\.]+)",
        version_extract: Some(r"Cherokee $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Tornado/([\d\.]+)",
        version_extract: Some(r"Tornado $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Jetty\(([^\)]+)\)",
        version_extract: Some(r"Jetty $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: WEBrick/([\d\.]+)",
        version_extract: Some(r"WEBrick $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Thin ([\d\.]+)",
        version_extract: Some(r"Thin $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Puma ([\d\.]+)",
        version_extract: Some(r"Puma $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Unicorn ([\d\.]+)",
        version_extract: Some(r"Unicorn $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Gunicorn/([\d\.]+)",
        version_extract: Some(r"Gunicorn $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: uWSGI/([\d\.]+)",
        version_extract: Some(r"uWSGI $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Kestrel",
        version_extract: Some(r"Kestrel (.NET)"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Mongoose/([\d\.]+)",
        version_extract: Some(r"Mongoose $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: GoAhead-Webs",
        version_extract: Some(r"GoAhead WebServer"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: thttpd/([\d\.]+)",
        version_extract: Some(r"thttpd $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: mini_httpd/([\d\.]+)",
        version_extract: Some(r"mini_httpd $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: SimpleHTTP/([\d\.]+)",
        version_extract: Some(r"Python SimpleHTTPServer $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Werkzeug/([\d\.]+)",
        version_extract: Some(r"Werkzeug $1 (Python)"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: CherryPy/([\d\.]+)",
        version_extract: Some(r"CherryPy $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Tomcat/([\d\.]+)",
        version_extract: Some(r"Apache Tomcat $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: Apache-Coyote/([\d\.]+)",
        version_extract: Some(r"Apache Tomcat Coyote $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: GlassFish Server",
        version_extract: Some(r"GlassFish Server"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: WebLogic",
        version_extract: Some(r"Oracle WebLogic"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: WebSphere",
        version_extract: Some(r"IBM WebSphere"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: JBoss",
        version_extract: Some(r"JBoss Application Server"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: WildFly/([\d\.]+)",
        version_extract: Some(r"WildFly $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"X-Powered-By: PHP/([\d\.]+)",
        version_extract: Some(r"PHP $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"X-Powered-By: ASP\.NET",
        version_extract: Some(r"ASP.NET"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"X-Powered-By: Express",
        version_extract: Some(r"Express.js (Node.js)"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"X-AspNet-Version: ([\d\.]+)",
        version_extract: Some(r"ASP.NET $1"),
    },
    // Additional application framework detection
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"X-Powered-By: Laravel",
        version_extract: Some(r"Laravel (PHP Framework)"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"X-Powered-By: Django/([\d\.]+)",
        version_extract: Some(r"Django $1 (Python)"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"X-Powered-By: Ruby on Rails ([\d\.]+)",
        version_extract: Some(r"Ruby on Rails $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"X-Generator: Drupal ([\d\.]+)",
        version_extract: Some(r"Drupal $1 (CMS)"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"X-Powered-By: WordPress",
        version_extract: Some(r"WordPress (CMS)"),
    },
    ServiceMatch {
        probe_name: "HTTPHead",
        service: "http",
        pattern: r"X-Powered-By: PHP/([\d\.]+)",
        version_extract: Some(r"PHP $1"),
    },
    ServiceMatch {
        probe_name: "HTTPHead",
        service: "http",
        pattern: r"Server: Apache/([\d\.]+)",
        version_extract: Some(r"Apache $1"),
    },
    ServiceMatch {
        probe_name: "HTTPHead",
        service: "http",
        pattern: r"Server: Microsoft-IIS/([\d\.]+)",
        version_extract: Some(r"IIS $1"),
    },
    
    // ============ ADVANCED HTTP DETECTION (30+) ============
    // HTTPVerbose probe patterns
    ServiceMatch {
        probe_name: "HTTPVerbose",
        service: "http",
        pattern: r"Server: nginx/([\d\.]+)",
        version_extract: Some(r"nginx $1"),
    },
    ServiceMatch {
        probe_name: "HTTPVerbose",
        service: "http",
        pattern: r"(?i)Server:\s*nginx\s*(?:\r|\n|$)",
        version_extract: Some(r"nginx (version hidden)"),
    },
    ServiceMatch {
        probe_name: "HTTPVerbose",
        service: "http",
        pattern: r"Server: Apache/([\d\.]+)\s+\(([^)]+)\)",
        version_extract: Some(r"Apache $1 ($2)"),
    },
    ServiceMatch {
        probe_name: "HTTPVerbose",
        service: "http",
        pattern: r"X-Powered-By: PHP/([\d\.]+)",
        version_extract: Some(r"PHP $1"),
    },
    ServiceMatch {
        probe_name: "HTTPVerbose",
        service: "http",
        pattern: r"X-AspNetMvc-Version: ([\d\.]+)",
        version_extract: Some(r"ASP.NET MVC $1"),
    },
    ServiceMatch {
        probe_name: "HTTPVerbose",
        service: "http",
        pattern: r"X-Drupal-Cache",
        version_extract: Some(r"Drupal CMS"),
    },
    ServiceMatch {
        probe_name: "HTTPVerbose",
        service: "http",
        pattern: r"X-Varnish",
        version_extract: Some(r"Varnish Cache"),
    },
    ServiceMatch {
        probe_name: "HTTPVerbose",
        service: "http",
        pattern: r"X-Amz-Cf-Id",
        version_extract: Some(r"Amazon CloudFront CDN"),
    },
    ServiceMatch {
        probe_name: "HTTPVerbose",
        service: "http",
        pattern: r"CF-RAY",
        version_extract: Some(r"Cloudflare CDN"),
    },
    ServiceMatch {
        probe_name: "HTTPVerbose",
        service: "http",
        pattern: r"X-Cache.*Akamai",
        version_extract: Some(r"Akamai CDN"),
    },
    
    // HTTPRobots probe patterns
    ServiceMatch {
        probe_name: "HTTPRobots",
        service: "http",
        pattern: r"User-agent:.*Disallow:",
        version_extract: Some(r"robots.txt found (web crawler rules)"),
    },
    ServiceMatch {
        probe_name: "HTTPRobots",
        service: "http",
        pattern: r"Sitemap:",
        version_extract: Some(r"robots.txt with sitemap"),
    },
    
    // HTTPServerStatus probe patterns
    ServiceMatch {
        probe_name: "HTTPServerStatus",
        service: "http",
        pattern: r"Apache Server Status",
        version_extract: Some(r"Apache (status page exposed)"),
    },
    ServiceMatch {
        probe_name: "HTTPServerStatus",
        service: "http",
        pattern: r"nginx status",
        version_extract: Some(r"nginx (status page exposed)"),
    },
    
    // HTTPTrace probe patterns
    ServiceMatch {
        probe_name: "HTTPTrace",
        service: "http",
        pattern: r"HTTP/1\.[01] 200.*TRACE",
        version_extract: Some(r"HTTP TRACE enabled (security risk)"),
    },
    
    // Common web technologies detection
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"X-Forwarded-For",
        version_extract: Some(r"Behind reverse proxy"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"X-Load-Balancer",
        version_extract: Some(r"Load balanced"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Via:.*squid",
        version_extract: Some(r"Squid Proxy"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: gunicorn/([\d\.]+)",
        version_extract: Some(r"Gunicorn $1 (Python WSGI)"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Server: uvicorn",
        version_extract: Some(r"Uvicorn (FastAPI/Python)"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"X-Next-JS",
        version_extract: Some(r"Next.js (React Framework)"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"X-Nuxt",
        version_extract: Some(r"Nuxt.js (Vue Framework)"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"X-Gatsby",
        version_extract: Some(r"Gatsby (React Static)"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"x-vercel-id",
        version_extract: Some(r"Vercel Hosting Platform"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"x-netlify",
        version_extract: Some(r"Netlify Hosting Platform"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"X-Heroku",
        version_extract: Some(r"Heroku Platform"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"X-GitHub-Request-Id",
        version_extract: Some(r"GitHub Pages"),
    },
    
    // Content-based detection (HTML body analysis)
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"wp-content/themes",
        version_extract: Some(r"WordPress CMS (theme detected)"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"wp-includes/",
        version_extract: Some(r"WordPress CMS"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Joomla!",
        version_extract: Some(r"Joomla! CMS"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"/sites/default/files",
        version_extract: Some(r"Drupal CMS (path detected)"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Powered by Shopify",
        version_extract: Some(r"Shopify E-commerce"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"WooCommerce",
        version_extract: Some(r"WooCommerce (WordPress)"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Magento",
        version_extract: Some(r"Magento E-commerce"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"PrestaShop",
        version_extract: Some(r"PrestaShop E-commerce"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"OpenCart",
        version_extract: Some(r"OpenCart E-commerce"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r#"<meta name="generator" content="([^"]+)""#,
        version_extract: Some(r"Generator: $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r#"ng-version="([\d\.]+)""#,
        version_extract: Some(r"Angular $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"data-react-helmet",
        version_extract: Some(r"React (with Helmet)"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"__NEXT_DATA__",
        version_extract: Some(r"Next.js Framework"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"__nuxt",
        version_extract: Some(r"Nuxt.js Framework"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Laravel",
        version_extract: Some(r"Laravel Framework"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Flask",
        version_extract: Some(r"Flask (Python)"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "http",
        pattern: r"Express",
        version_extract: Some(r"Express.js (Node.js)"),
    },
    
    // ============ FTP SIGNATURES (10) ============
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
        version_extract: Some(r"FileZilla Server $1"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ftp",
        pattern: r"220.*Pure-FTPd",
        version_extract: Some(r"Pure-FTPd"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ftp",
        pattern: r"220.*Microsoft FTP Service",
        version_extract: Some(r"Microsoft FTP Service"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ftp",
        pattern: r"220.*Gene6 FTP Server",
        version_extract: Some(r"Gene6 FTP Server"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ftp",
        pattern: r"220.*Serv-U FTP Server",
        version_extract: Some(r"Serv-U FTP Server"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ftp",
        pattern: r"220.*Wu-FTPd",
        version_extract: Some(r"Wu-FTPd"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "ftp",
        pattern: r"220.*Titan FTP Server",
        version_extract: Some(r"Titan FTP Server"),
    },
    
    // ============ SMTP SIGNATURES (12) ============
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
        probe_name: "NULL",
        service: "smtp",
        pattern: r"220.*Sendmail ([\d\.]+)",
        version_extract: Some(r"Sendmail $1"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "smtp",
        pattern: r"220.*Microsoft ESMTP MAIL Service",
        version_extract: Some(r"Microsoft Exchange"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "smtp",
        pattern: r"220.*qmail",
        version_extract: Some(r"qmail"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "smtp",
        pattern: r"220.*Courier",
        version_extract: Some(r"Courier MTA"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "smtp",
        pattern: r"220.*Zimbra",
        version_extract: Some(r"Zimbra"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "smtp",
        pattern: r"220.*hMailServer",
        version_extract: Some(r"hMailServer"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "smtp",
        pattern: r"220.*MailEnable",
        version_extract: Some(r"MailEnable"),
    },
    ServiceMatch {
        probe_name: "SMTPHelo",
        service: "smtp",
        pattern: r"250.*ESMTP",
        version_extract: None,
    },
    ServiceMatch {
        probe_name: "SMTPHelo",
        service: "smtp",
        pattern: r"250-PIPELINING",
        version_extract: Some(r"SMTP with PIPELINING"),
    },
    
    // ============ DATABASE SIGNATURES (25) ============
    // MySQL
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
    ServiceMatch {
        probe_name: "NULL",
        service: "mysql",
        pattern: r"([\d\.]+)-MariaDB",
        version_extract: Some(r"MariaDB $1"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "mysql",
        pattern: r"([\d\.]+)-MySQL",
        version_extract: Some(r"MySQL $1"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "mysql",
        pattern: r"([\d\.]+)-Percona",
        version_extract: Some(r"Percona Server $1"),
    },
    
    // PostgreSQL
    ServiceMatch {
        probe_name: "PostgreSQLStartup",
        service: "postgresql",
        pattern: r"FATAL",
        version_extract: Some(r"PostgreSQL"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "postgresql",
        pattern: r"PostgreSQL ([\d\.]+)",
        version_extract: Some(r"PostgreSQL $1"),
    },
    
    // Redis
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
    ServiceMatch {
        probe_name: "RedisInfo",
        service: "redis",
        pattern: r"redis_mode:(standalone|sentinel|cluster)",
        version_extract: Some(r"Redis ($1 mode)"),
    },
    
    // MongoDB
    ServiceMatch {
        probe_name: "MongoDBHello",
        service: "mongodb",
        pattern: r#""ok"\s*:\s*1"#,
        version_extract: Some(r"MongoDB"),
    },
    ServiceMatch {
        probe_name: "MongoDBHello",
        service: "mongodb",
        pattern: r#""version"\s*:\s*"([\d\.]+)""#,
        version_extract: Some(r"MongoDB $1"),
    },
    
    // Memcached
    ServiceMatch {
        probe_name: "MemcachedVersion",
        service: "memcached",
        pattern: r"VERSION ([\d\.]+)",
        version_extract: Some(r"Memcached $1"),
    },
    
    // Cassandra
    ServiceMatch {
        probe_name: "GenericLines",
        service: "cassandra",
        pattern: r"CQL_VERSION",
        version_extract: Some(r"Apache Cassandra"),
    },
    
    // CouchDB
    ServiceMatch {
        probe_name: "GetRequest",
        service: "couchdb",
        pattern: r#""couchdb"\s*:\s*"Welcome""#,
        version_extract: Some(r"Apache CouchDB"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "couchdb",
        pattern: r#""version"\s*:\s*"([\d\.]+)""#,
        version_extract: Some(r"CouchDB $1"),
    },
    
    // Elasticsearch
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
    ServiceMatch {
        probe_name: "GetRequest",
        service: "elasticsearch",
        pattern: r#""lucene_version"\s*:\s*"([\d\.]+)""#,
        version_extract: Some(r"Elasticsearch (Lucene $1)"),
    },
    
    // InfluxDB
    ServiceMatch {
        probe_name: "GetRequest",
        service: "influxdb",
        pattern: r"X-Influxdb-Version: ([\d\.]+)",
        version_extract: Some(r"InfluxDB $1"),
    },
    
    // Neo4j
    ServiceMatch {
        probe_name: "GetRequest",
        service: "neo4j",
        pattern: r"Neo4j/([\d\.]+)",
        version_extract: Some(r"Neo4j $1"),
    },
    
    // Oracle
    ServiceMatch {
        probe_name: "NULL",
        service: "oracle",
        pattern: r"Oracle",
        version_extract: Some(r"Oracle Database"),
    },
    
    // Microsoft SQL Server
    ServiceMatch {
        probe_name: "NULL",
        service: "mssql",
        pattern: r"Microsoft SQL Server",
        version_extract: Some(r"Microsoft SQL Server"),
    },
    
    // ============ POP3/IMAP SIGNATURES (8) ============
    ServiceMatch {
        probe_name: "NULL",
        service: "pop3",
        pattern: r"^\+OK",
        version_extract: None,
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "pop3",
        pattern: r"\+OK.*Dovecot",
        version_extract: Some(r"Dovecot POP3"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "pop3",
        pattern: r"\+OK.*Courier",
        version_extract: Some(r"Courier POP3"),
    },
    ServiceMatch {
        probe_name: "POP3Capabilities",
        service: "pop3",
        pattern: r"^\+OK",
        version_extract: None,
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "imap",
        pattern: r"\* OK.*IMAP",
        version_extract: None,
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "imap",
        pattern: r"\* OK.*Dovecot",
        version_extract: Some(r"Dovecot IMAP"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "imap",
        pattern: r"\* OK.*Courier",
        version_extract: Some(r"Courier IMAP"),
    },
    ServiceMatch {
        probe_name: "IMAPCapabilities",
        service: "imap",
        pattern: r"\* CAPABILITY",
        version_extract: None,
    },
    
    // ============ REMOTE ACCESS SIGNATURES (6) ============
    ServiceMatch {
        probe_name: "VNCHandshake",
        service: "vnc",
        pattern: r"^RFB \d{3}\.\d{3}",
        version_extract: None,
    },
    ServiceMatch {
        probe_name: "VNCHandshake",
        service: "vnc",
        pattern: r"^RFB 003\.008",
        version_extract: Some(r"VNC RFB 3.8"),
    },
    ServiceMatch {
        probe_name: "VNCHandshake",
        service: "vnc",
        pattern: r"^RFB 003\.007",
        version_extract: Some(r"VNC RFB 3.7"),
    },
    ServiceMatch {
        probe_name: "RDPInitial",
        service: "ms-wbt-server",
        pattern: r"\x03\x00\x00",
        version_extract: Some(r"RDP"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "telnet",
        pattern: r"\xff\xfd",
        version_extract: Some(r"Telnet"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "telnet",
        pattern: r"Welcome to",
        version_extract: Some(r"Telnet"),
    },
    
    // ============ MESSAGING & STREAMING (8) ============
    ServiceMatch {
        probe_name: "ZookeeperStat",
        service: "zookeeper",
        pattern: r"Zookeeper version: ([\d\.\-\w]+)",
        version_extract: Some(r"Zookeeper $1"),
    },
    ServiceMatch {
        probe_name: "ZookeeperStat",
        service: "zookeeper",
        pattern: r"Mode: (standalone|leader|follower)",
        version_extract: Some(r"Zookeeper ($1)"),
    },
    ServiceMatch {
        probe_name: "RTSPRequest",
        service: "rtsp",
        pattern: r"RTSP/1\.0 200 OK",
        version_extract: Some(r"RTSP Server"),
    },
    ServiceMatch {
        probe_name: "RTSPRequest",
        service: "rtsp",
        pattern: r"Server: ([\w\-]+)",
        version_extract: Some(r"RTSP Server $1"),
    },
    ServiceMatch {
        probe_name: "SIPOptions",
        service: "sip",
        pattern: r"SIP/2\.0 200 OK",
        version_extract: Some(r"SIP Server"),
    },
    ServiceMatch {
        probe_name: "SIPOptions",
        service: "sip",
        pattern: r"User-Agent: ([\w\-\s]+)",
        version_extract: Some(r"SIP $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "rabbitmq",
        pattern: r"RabbitMQ",
        version_extract: Some(r"RabbitMQ"),
    },
    ServiceMatch {
        probe_name: "NULL",
        service: "mqtt",
        pattern: r"MQTT",
        version_extract: Some(r"MQTT Broker"),
    },
    
    // ============ CONTAINER & ORCHESTRATION (10) ============
    ServiceMatch {
        probe_name: "DockerVersion",
        service: "docker",
        pattern: r#""Version":"([\d\.]+)""#,
        version_extract: Some(r"Docker $1"),
    },
    ServiceMatch {
        probe_name: "DockerVersion",
        service: "docker",
        pattern: r#""ApiVersion":"([\d\.]+)""#,
        version_extract: Some(r"Docker API $1"),
    },
    ServiceMatch {
        probe_name: "DockerVersion",
        service: "docker",
        pattern: r#""Os":"(\w+)""#,
        version_extract: Some(r"Docker on $1"),
    },
    ServiceMatch {
        probe_name: "KubernetesVersion",
        service: "kubernetes",
        pattern: r#""major":"(\d+)","minor":"(\d+)""#,
        version_extract: Some(r"Kubernetes $1.$2"),
    },
    ServiceMatch {
        probe_name: "KubernetesVersion",
        service: "kubernetes",
        pattern: r#""gitVersion":"v([\d\.]+)""#,
        version_extract: Some(r"Kubernetes $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "etcd",
        pattern: r#""etcdserver":"([\d\.]+)""#,
        version_extract: Some(r"etcd $1"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "consul",
        pattern: r"Consul Agent",
        version_extract: Some(r"HashiCorp Consul"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "vault",
        pattern: r"Vault",
        version_extract: Some(r"HashiCorp Vault"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "nomad",
        pattern: r"Nomad",
        version_extract: Some(r"HashiCorp Nomad"),
    },
    ServiceMatch {
        probe_name: "GetRequest",
        service: "minio",
        pattern: r"MinIO",
        version_extract: Some(r"MinIO Object Storage"),
    },
];
/// Execute probes against a target port with Nmap-style progressive probing
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

    let mut best_result: Option<ProbeResult> = None;
    let mut best_confidence = 0u8;

    // Nmap strategy: Try multiple probes and keep the best result
    for probe in applicable_probes {
        if let Some(result) = try_probe(target, port, probe, timeout).await {
            // Try to match response against service signatures
            if let Some(matched) = match_response(&result.response, probe.name) {
                let current_confidence = matched.2;
                
                // Keep result if confidence is better OR if we don't have one yet
                if current_confidence > best_confidence || best_result.is_none() {
                    best_confidence = current_confidence;
                    best_result = Some(ProbeResult {
                        probe_name: probe.name.to_string(),
                        response: result.response.clone(),
                        service_identified: Some(matched.0),
                        version: matched.1,
                        confidence: matched.2,
                    });
                    
                    // If confidence is very high (>90), we can stop early
                    if current_confidence >= 95 {
                        return best_result;
                    }
                }
            } else if best_result.is_none() {
                // No match yet, but save the response for fallback
                best_result = Some(result);
            }
        }
    }
    
    // Fallback: If we got response but no match, try generic detection
    if let Some(mut result) = best_result {
        if result.service_identified.is_none() {
            // Nmap-style fallback: detect service type from response content and port
            let response_lower = result.response.to_lowercase();
            
            // Check for SSL/TLS encrypted data (binary response on HTTPS ports)
            if (port == 443 || port == 8443) && !response_lower.starts_with("http") {
                // Likely TLS/SSL encrypted - common on 443
                if result.response.len() > 0 && !result.response.is_ascii() {
                    result.service_identified = Some("ssl/http".to_string());
                    result.version = Some("HTTPS".to_string());
                    result.confidence = 75;
                    return Some(result);
                }
            }
            
            // HTTP detection - Nmap-style concise descriptions
            if response_lower.starts_with("http/1.1") {
                result.service_identified = Some("http".to_string());
                result.version = Some("HTTP/1.1".to_string());
                result.confidence = 70;
            } else if response_lower.starts_with("http/1.0") {
                result.service_identified = Some("http".to_string());
                result.version = Some("HTTP/1.0".to_string());
                result.confidence = 70;
            } else if response_lower.starts_with("http/2") {
                result.service_identified = Some("http".to_string());
                result.version = Some("HTTP/2".to_string());
                result.confidence = 70;
            } else if response_lower.contains("content-type:") {
                // Detect content type for better clarity
                if response_lower.contains("content-type: text/html") {
                    result.service_identified = Some("http".to_string());
                    result.version = Some("HTML document".to_string());
                    result.confidence = 60;
                } else if response_lower.contains("content-type: application/json") {
                    result.service_identified = Some("http".to_string());
                    result.version = Some("HTTP API".to_string());
                    result.confidence = 60;
                } else {
                    result.service_identified = Some("http".to_string());
                    result.confidence = 55;
                }
            }
            // SSH detection
            else if response_lower.starts_with("ssh-") {
                result.service_identified = Some("ssh".to_string());
                result.confidence = 85;
            } 
            // FTP detection
            else if response_lower.contains("220 ") && response_lower.contains("ftp") {
                result.service_identified = Some("ftp".to_string());
                result.confidence = 70;
            } 
            // SMTP detection
            else if response_lower.contains("220 ") && response_lower.contains("smtp") {
                result.service_identified = Some("smtp".to_string());
                result.confidence = 70;
            } 
            // POP3 detection
            else if response_lower.contains("+ok") {
                result.service_identified = Some("pop3".to_string());
                result.confidence = 65;
            } 
            // IMAP detection
            else if response_lower.contains("* ok") && response_lower.contains("imap") {
                result.service_identified = Some("imap".to_string());
                result.confidence = 70;
            }
            // Port-based fallback for common services (last resort)
            else if port == 80 || port == 8080 || port == 8000 {
                result.service_identified = Some("http".to_string());
                result.version = Some("HTTP".to_string());
                result.confidence = 50;
            } else if port == 443 || port == 8443 {
                result.service_identified = Some("ssl/http".to_string());
                result.version = Some("HTTPS".to_string());
                result.confidence = 50;
            }
        }
        return Some(result);
    }

    None
}

/// Try a single probe with Nmap-style spontaneous banner reading
async fn try_probe(
    target: &str,
    port: u16,
    probe: &ServiceProbe,
    timeout: Duration,
) -> Option<ProbeResult> {
    let socket_addr = format!("{}:{}", target, port);
    
    match tokio::time::timeout(timeout, TcpStream::connect(&socket_addr)).await {
        Ok(Ok(mut stream)) => {
            // Nmap-style: For NULL probe, wait for spontaneous banner first
            if probe.data.is_empty() {
                // Wait for server to send banner (many services send it immediately)
                let mut buffer = vec![0u8; 16384];
                
                match tokio::time::timeout(
                    Duration::from_millis(500), // Wait 500ms for spontaneous banner
                    stream.read(&mut buffer)
                ).await {
                    Ok(Ok(n)) if n > 0 => {
                        let response = String::from_utf8_lossy(&buffer[..n]).to_string();
                        return Some(ProbeResult {
                            probe_name: probe.name.to_string(),
                            response,
                            service_identified: None,
                            version: None,
                            confidence: 0,
                        });
                    }
                    _ => {
                        // No spontaneous banner, this is OK for NULL probe
                        return None;
                    }
                }
            }
            
            // Send probe data (for non-NULL probes)
            if stream.write_all(probe.data).await.is_err() {
                return None;
            }
            
            // Read response with larger buffer for HTTP headers
            let mut buffer = vec![0u8; 16384];
            let mut total_read = 0;
            
            // Progressive reading - like Nmap's soft matching
            // Read in chunks until we get complete response or timeout
            let start_time = std::time::Instant::now();
            let read_timeout = Duration::from_millis(200); // Adaptive timeout per chunk
            
            loop {
                // Check overall timeout
                if start_time.elapsed() > timeout {
                    break;
                }
                
                match tokio::time::timeout(
                    read_timeout,
                    stream.read(&mut buffer[total_read..])
                ).await {
                    Ok(Ok(n)) if n > 0 => {
                        total_read += n;
                        
                        // Stop if buffer is full
                        if total_read >= buffer.len() - 1 {
                            break;
                        }
                        
                        // For HTTP responses, check if we got complete headers
                        let response_so_far = String::from_utf8_lossy(&buffer[..total_read]);
                        if response_so_far.starts_with("HTTP/") {
                            // HTTP response detected
                            if response_so_far.contains("\r\n\r\n") {
                                // Got complete HTTP headers
                                // Read a bit more to get some body content for fingerprinting
                                match tokio::time::timeout(
                                    Duration::from_millis(50),
                                    stream.read(&mut buffer[total_read..])
                                ).await {
                                    Ok(Ok(body_bytes)) if body_bytes > 0 => {
                                        total_read += body_bytes;
                                    }
                                    _ => {}
                                }
                                break;
                            }
                        } else if response_so_far.contains("\n") && total_read > 100 {
                            // For non-HTTP responses, if we got a newline and some data, that's usually enough
                            // One more short read attempt
                            match tokio::time::timeout(
                                Duration::from_millis(50),
                                stream.read(&mut buffer[total_read..])
                            ).await {
                                Ok(Ok(extra)) if extra > 0 => {
                                    total_read += extra;
                                }
                                _ => {}
                            }
                            break;
                        }
                    }
                    Ok(Ok(_)) => break, // Connection closed by server (0 bytes or other)
                    Ok(Err(_)) => break, // Read error
                    Err(_) => {
                        // Timeout on this read, but we might have data
                        if total_read > 0 {
                            break;
                        } else {
                            return None;
                        }
                    }
                }
            }
            
            if total_read > 0 {
                let response = String::from_utf8_lossy(&buffer[..total_read]).to_string();
                Some(ProbeResult {
                    probe_name: probe.name.to_string(),
                    response,
                    service_identified: None,
                    version: None,
                    confidence: 0,
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Match response against service signatures - Nmap-style soft matching with priorities
/// Returns BEST match considering: version info > specific patterns > generic patterns
fn match_response(response: &str, probe_name: &str) -> Option<(String, Option<String>, u8)> {
    let mut best_match: Option<(String, Option<String>, u8)> = None;
    let mut best_score = 0u8;
    
    // Nmap strategy: Try all patterns and score them
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
                
                // Nmap-style scoring: base confidence by probe type
                let base_confidence = match probe_name {
                    "NULL" => 95,  // Highest confidence - spontaneous banner
                    "GetRequest" | "HTTPHead" | "HTTPVerbose" => 90, // HTTP probes
                    "SSHVersionExchange" | "SMTPHelo" => 90, // Protocol-specific
                    "GenericLines" => 75, // Generic probe
                    "FTPUser" | "POP3Capabilities" => 85,
                    _ => 80,
                };
                
                // Score boosting (Nmap soft matching priorities):
                let mut score = base_confidence;
                
                // 1. Pattern specificity: longer patterns = more specific
                let pattern_length = sig.pattern.len();
                if pattern_length > 50 {
                    score += 5; // Very specific pattern
                } else if pattern_length > 30 {
                    score += 3; // Moderately specific
                }
                
                // 2. Version extraction: highly preferred
                if version.is_some() {
                    score += 15; // Strong preference for version info
                    
                    // Bonus for known vendor names even without numeric version
                    let version_lower = version.as_ref().unwrap().to_lowercase();
                    if version_lower.contains("nginx") || version_lower.contains("apache") || 
                       version_lower.contains("iis") || version_lower.contains("lighttpd") ||
                       version_lower.contains("caddy") || version_lower.contains("litespeed") {
                        score += 10; // Known vendor = higher priority
                    }
                }
                
                // 3. Exact service name match in pattern (not just HTTP/FTP)
                if sig.service != "http" && sig.service != "https" && sig.service != "unknown" {
                    score += 5; // Specific service better than generic
                }
                
                // 4. Multiple capture groups = detailed info
                if captures.len() > 2 {
                    score += 5; // Detailed extraction
                }
                
                // Keep best match (highest score)
                if score > best_score {
                    best_score = score;
                    best_match = Some((sig.service.to_string(), version, score)); // Return actual score, not base
                }
            }
        }
    }
    
    best_match
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
