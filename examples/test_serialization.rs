// test_serialization.rs
// Quick test to verify Port struct serialization with new fields

use serde_json;

#[allow(dead_code)]
fn main() {
    use nextmap::models::*;
    
    let port = Port {
        port_id: 6379,
        protocol: "tcp".to_string(),
        state: PortState::Open,
        service_name: Some("redis".to_string()),
        service_version: Some("Redis 7.0.5".to_string()),
        banner: Some("redis_version:7.0.5".to_string()),
        service_category: Some(ServiceCategory::Cache),
        risk_level: Some(RiskLevel::High),
        detection_method: Some(DetectionMethod::EnhancedProbe),
        cve_count: Some(0),
        full_banner: Some("+$70\\r\\nredis_version:7.0.5...".to_string()),
    };
    
    let json = serde_json::to_string_pretty(&port).unwrap();
    println!("{}", json);
}
