// src/output/html.rs
// Professional HTML report generation for NextMap scans

use crate::models::*;
use std::collections::HashMap;

/// Generates a professional HTML report from scan results
pub fn generate_html_report(scan_results: &ScanResult) -> String {
    let mut html = String::new();
    
    // Calculate statistics
    let stats = calculate_statistics(scan_results);
    
    // HTML header and CSS
    html.push_str(&html_header());
    
    // Report header with scan summary
    html.push_str(&report_header(scan_results, &stats));
    
    // Risk summary cards
    html.push_str(&risk_summary_cards(&stats));
    
    // Detection methods summary (if Nuclei or multiple methods used)
    html.push_str(&detection_methods_summary(&stats));
    
    // Grouped services table
    html.push_str(&services_by_category_table(scan_results));
    
    // Vulnerabilities section
    html.push_str(&vulnerabilities_section(scan_results));
    
    // Footer
    html.push_str(&html_footer());
    
    html
}

/// Statistics structure for the report
struct ScanStatistics {
    total_hosts: usize,
    total_ports_scanned: usize,
    open_ports: usize,
    services_detected: usize,
    critical_risk: usize,
    high_risk: usize,
    medium_risk: usize,
    low_risk: usize,
    total_cves: usize,
    categories: HashMap<String, usize>,
    detection_methods: HashMap<String, usize>,
}

fn calculate_statistics(scan_results: &ScanResult) -> ScanStatistics {
    let mut stats = ScanStatistics {
        total_hosts: scan_results.hosts.len(),
        total_ports_scanned: 0,
        open_ports: 0,
        services_detected: 0,
        critical_risk: 0,
        high_risk: 0,
        medium_risk: 0,
        low_risk: 0,
        total_cves: 0,
        categories: HashMap::new(),
        detection_methods: HashMap::new(),
    };
    
    for host in &scan_results.hosts {
        stats.total_ports_scanned += host.ports.len();
        
        for port in &host.ports {
            if port.state == PortState::Open {
                stats.open_ports += 1;
            }
            
            if port.service_name.is_some() {
                stats.services_detected += 1;
            }
            
            // Count by risk level
            if let Some(ref risk) = port.risk_level {
                match risk {
                    RiskLevel::Critical => stats.critical_risk += 1,
                    RiskLevel::High => stats.high_risk += 1,
                    RiskLevel::Medium => stats.medium_risk += 1,
                    RiskLevel::Low => stats.low_risk += 1,
                    RiskLevel::Info => {},
                }
            }
            
            // Count CVEs
            if let Some(cve_count) = port.cve_count {
                stats.total_cves += cve_count;
            }
            
            // Count by category
            if let Some(ref category) = port.service_category {
                let cat_name = category.display_name().to_string();
                *stats.categories.entry(cat_name).or_insert(0) += 1;
            }
            
            // Count by detection method
            if let Some(ref method) = port.detection_method {
                let method_name = method.display_name().to_string();
                *stats.detection_methods.entry(method_name).or_insert(0) += 1;
            }
        }
        
        stats.total_cves += host.vulnerabilities.len();
    }
    
    stats
}

fn html_header() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NextMap Scan Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.15);
        }
        
        .stat-card h3 {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }
        
        .stat-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }
        
        .risk-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            padding: 20px 30px;
        }
        
        .risk-card {
            padding: 15px;
            border-radius: 8px;
            color: white;
            text-align: center;
        }
        
        .risk-critical { background: #dc3545; }
        .risk-high { background: #fd7e14; }
        .risk-medium { background: #ffc107; color: #333; }
        .risk-low { background: #28a745; }
        
        .risk-card .count {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .risk-card .label {
            font-size: 0.9em;
            opacity: 0.9;
        }
        
        .section {
            padding: 30px;
        }
        
        .section h2 {
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }
        
        .category-group {
            margin-bottom: 30px;
        }
        
        .category-header {
            background: #667eea;
            color: white;
            padding: 12px 20px;
            border-radius: 6px;
            font-size: 1.2em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        
        thead {
            background: #f8f9fa;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        
        th {
            font-weight: 600;
            color: #495057;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }
        
        tbody tr:hover {
            background: #f8f9fa;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }
        
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: #ffc107; color: #333; }
        .badge-low { background: #28a745; color: white; }
        .badge-info { background: #17a2b8; color: white; }
        
        .badge-open { background: #28a745; color: white; }
        .badge-closed { background: #6c757d; color: white; }
        .badge-filtered { background: #ffc107; color: #333; }
        
        /* Detection Method badges */
        .badge-detection-active { background: #9c27b0; color: white; font-weight: bold; }
        .badge-detection-passive { background: #2196f3; color: white; }
        .badge-detection-enhanced { background: #00bcd4; color: white; }
        .badge-detection-default { background: #607d8b; color: white; }
        
        .vuln-list {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 4px;
        }
        
        .vuln-item {
            margin-bottom: 10px;
        }
        
        .vuln-item:last-child {
            margin-bottom: 0;
        }
        
        .footer {
            background: #343a40;
            color: white;
            text-align: center;
            padding: 20px;
            font-size: 0.9em;
        }
        
        .footer a {
            color: #667eea;
            text-decoration: none;
        }
        
        code {
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
"#.to_string()
}

fn report_header(scan_results: &ScanResult, stats: &ScanStatistics) -> String {
    format!(r#"        <div class="header">
            <h1>🔍 NextMap Scan Report</h1>
            <p>{}</p>
            <p>Scan Duration: {} ms | Command: <code>{}</code></p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Hosts Scanned</h3>
                <div class="value">{}</div>
            </div>
            <div class="stat-card">
                <h3>Ports Scanned</h3>
                <div class="value">{}</div>
            </div>
            <div class="stat-card">
                <h3>Open Ports</h3>
                <div class="value">{}</div>
            </div>
            <div class="stat-card">
                <h3>Services Detected</h3>
                <div class="value">{}</div>
            </div>
            <div class="stat-card">
                <h3>Total CVEs</h3>
                <div class="value">{}</div>
            </div>
        </div>
"#,
        scan_results.timestamp,
        scan_results.duration_ms,
        scan_results.command,
        stats.total_hosts,
        stats.total_ports_scanned,
        stats.open_ports,
        stats.services_detected,
        stats.total_cves
    )
}

fn risk_summary_cards(stats: &ScanStatistics) -> String {
    format!(r#"        <div class="risk-cards">
            <div class="risk-card risk-critical">
                <div class="count">🔴 {}</div>
                <div class="label">Critical Risk</div>
            </div>
            <div class="risk-card risk-high">
                <div class="count">🟠 {}</div>
                <div class="label">High Risk</div>
            </div>
            <div class="risk-card risk-medium">
                <div class="count">🟡 {}</div>
                <div class="label">Medium Risk</div>
            </div>
            <div class="risk-card risk-low">
                <div class="count">🟢 {}</div>
                <div class="label">Low Risk</div>
            </div>
        </div>
"#,
        stats.critical_risk,
        stats.high_risk,
        stats.medium_risk,
        stats.low_risk
    )
}

fn detection_methods_summary(stats: &ScanStatistics) -> String {
    if stats.detection_methods.is_empty() {
        return String::new();
    }
    
    let mut html = String::from(r#"        <div class="section">
            <h3>🔬 Detection Methods Distribution</h3>
            <div class="stats-grid" style="grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); margin-top: 15px;">
"#);
    
    // Define method order and styling
    let method_order = [
        ("Active Scan (Nuclei)", "🎯", "badge-detection-active"),
        ("Enhanced Probe", "🔬", "badge-detection-enhanced"),
        ("Banner", "👁️", "badge-detection-passive"),
        ("Version Probe", "👁️", "badge-detection-passive"),
        ("Port Mapping", "🗺️", "badge-detection-passive"),
    ];
    
    for (method_name, icon, badge_class) in &method_order {
        if let Some(&count) = stats.detection_methods.get(*method_name) {
            html.push_str(&format!(r#"                <div class="stat-card">
                    <div class="badge {}" style="display: block; margin-bottom: 10px;">{} {}</div>
                    <div class="value" style="font-size: 2em;">{}</div>
                    <h3 style="margin-top: 5px;">Detections</h3>
                </div>
"#, badge_class, icon, method_name, count));
        }
    }
    
    html.push_str(r#"            </div>
        </div>
"#);
    
    html
}

fn services_by_category_table(scan_results: &ScanResult) -> String {
    let mut html = String::from(r#"        <div class="section">
            <h2>🎯 Services by Category</h2>
"#);
    
    // Group ports by category
    let mut categories: HashMap<String, Vec<(&Host, &Port)>> = HashMap::new();
    
    for host in &scan_results.hosts {
        for port in &host.ports {
            if port.state == PortState::Open {
                let category = port.service_category.as_ref()
                    .map(|c| c.display_name().to_string())
                    .unwrap_or_else(|| "Other".to_string());
                
                categories.entry(category).or_insert_with(Vec::new).push((host, port));
            }
        }
    }
    
    // Sort categories by name
    let mut sorted_cats: Vec<_> = categories.keys().collect();
    sorted_cats.sort();
    
    for category in sorted_cats {
        let ports = categories.get(category).unwrap();
        
        html.push_str(&format!(r#"            <div class="category-group">
                <div class="category-header">📂 {} ({} services)</div>
                <table>
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Port</th>
                            <th>Service</th>
                            <th>Version</th>
                            <th>Risk</th>
                            <th>Detection</th>
                            <th>CVEs</th>
                        </tr>
                    </thead>
                    <tbody>
"#, category, ports.len()));
        
        for (host, port) in ports {
            let risk_badge = port.risk_level.as_ref()
                .map(|r| format!("<span class=\"badge badge-{}\">{} {:?}</span>", 
                    match r {
                        RiskLevel::Critical => "critical",
                        RiskLevel::High => "high",
                        RiskLevel::Medium => "medium",
                        RiskLevel::Low => "low",
                        RiskLevel::Info => "info",
                    },
                    r.symbol(),
                    r
                ))
                .unwrap_or_else(|| "<span class=\"badge badge-info\">Unknown</span>".to_string());
            
            // Detection method with color-coded badge
            let detection_badge = port.detection_method.as_ref()
                .map(|d| {
                    let (badge_class, icon) = match d {
                        DetectionMethod::ActiveScan => ("badge-detection-active", "🎯"),
                        DetectionMethod::EnhancedProbe => ("badge-detection-enhanced", "🔬"),
                        DetectionMethod::VersionProbe | DetectionMethod::Banner => ("badge-detection-passive", "👁️"),
                        DetectionMethod::PortMapping => ("badge-detection-passive", "🗺️"),
                        DetectionMethod::Unknown => ("badge-detection-default", "❓"),
                    };
                    format!("<span class=\"badge {}\">{} {}</span>", badge_class, icon, d.display_name())
                })
                .unwrap_or_else(|| "<span class=\"badge badge-detection-default\">❓ Unknown</span>".to_string());
            
            html.push_str(&format!(r#"                        <tr>
                            <td><code>{}</code></td>
                            <td><strong>{}</strong></td>
                            <td>{}</td>
                            <td>{}</td>
                            <td>{}</td>
                            <td>{}</td>
                            <td>{}</td>
                        </tr>
"#,
                host.ip_address,
                port.port_id,
                port.service_name.as_deref().unwrap_or("unknown"),
                port.service_version.as_deref().unwrap_or("N/A"),
                risk_badge,
                detection_badge,
                port.cve_count.unwrap_or(0)
            ));
        }
        
        html.push_str(r#"                    </tbody>
                </table>
            </div>
"#);
    }
    
    html.push_str("        </div>\n");
    html
}

fn vulnerabilities_section(scan_results: &ScanResult) -> String {
    let mut html = String::from(r#"        <div class="section">
            <h2>⚠️ Vulnerabilities</h2>
"#);
    
    let mut has_vulns = false;
    
    for host in &scan_results.hosts {
        if !host.vulnerabilities.is_empty() {
            has_vulns = true;
            html.push_str(&format!(r#"            <h3>Host: <code>{}</code></h3>
"#, host.ip_address));
            
            for vuln in &host.vulnerabilities {
                let severity_class = match vuln.severity.to_lowercase().as_str() {
                    "critical" => "critical",
                    "high" => "high",
                    "medium" => "medium",
                    "low" => "low",
                    _ => "info",
                };
                
                html.push_str(&format!(r#"            <div class="vuln-list">
                <div class="vuln-item">
                    <strong>{}</strong> <span class="badge badge-{}">{}</span>
                    <br>Port: {} | {}
                </div>
            </div>
"#,
                    vuln.cve_id,
                    severity_class,
                    vuln.severity,
                    vuln.service_port,
                    vuln.description_short
                ));
            }
        }
    }
    
    if !has_vulns {
        html.push_str(r#"            <p>✅ No vulnerabilities detected.</p>
"#);
    }
    
    html.push_str("        </div>\n");
    html
}

fn html_footer() -> String {
    r#"        <div class="footer">
            <p>Generated by <a href="https://github.com/pozivo/nextmap" target="_blank">NextMap v0.3.1</a></p>
            <p>Professional Network Security Scanner</p>
        </div>
    </div>
</body>
</html>"#.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_html_generation() {
        let scan_results = ScanResult {
            timestamp: "2025-01-01T12:00:00Z".to_string(),
            command: "nextmap -t 192.168.1.1 -p 1-1000".to_string(),
            duration_ms: 5000,
            hosts: vec![],
        };
        
        let html = generate_html_report(&scan_results);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("NextMap Scan Report"));
        assert!(html.contains("</html>"));
    }
}
