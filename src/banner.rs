// src/banner.rs
// ASCII Art Banner for NextMap

use colored::*;

/// Display the NextMap ASCII art banner with version info
pub fn print_banner(version: &str) {
    let banner = r#"
 ███╗   ██╗███████╗██╗  ██╗████████╗███╗   ███╗ █████╗ ██████╗ 
 ████╗  ██║██╔════╝╚██╗██╔╝╚══██╔══╝████╗ ████║██╔══██╗██╔══██╗
 ██╔██╗ ██║█████╗   ╚███╔╝    ██║   ██╔████╔██║███████║██████╔╝
 ██║╚██╗██║██╔══╝   ██╔██╗    ██║   ██║╚██╔╝██║██╔══██║██╔═══╝ 
 ██║ ╚████║███████╗██╔╝ ██╗   ██║   ██║ ╚═╝ ██║██║  ██║██║     
 ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
"#;
    
    println!("{}", banner.cyan().bold());
    println!("{}", format!("    🔍 Next Generation Network Scanner v{}", version).bright_yellow());
    println!("{}", "    Advanced Stealth • CVE Detection • Professional Output".bright_black());
    println!();
}

/// Display a compact banner for non-human output formats
pub fn print_compact_banner(version: &str) {
    println!("{}", format!("NextMap v{} - Network Scanner", version).cyan());
}

/// Get banner text without colors (for file output)
pub fn get_banner_text(version: &str) -> String {
    format!(
        r#"
 ███╗   ██╗███████╗██╗  ██╗████████╗███╗   ███╗ █████╗ ██████╗ 
 ████╗  ██║██╔════╝╚██╗██╔╝╚══██╔══╝████╗ ████║██╔══██╗██╔══██╗
 ██╔██╗ ██║█████╗   ╚███╔╝    ██║   ██╔████╔██║███████║██████╔╝
 ██║╚██╗██║██╔══╝   ██╔██╗    ██║   ██║╚██╔╝██║██╔══██║██╔═══╝ 
 ██║ ╚████║███████╗██╔╝ ██╗   ██║   ██║ ╚═╝ ██║██║  ██║██║     
 ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
    
    🔍 Next Generation Network Scanner v{}
    Advanced Stealth • CVE Detection • Professional Output
"#,
        version
    )
}
