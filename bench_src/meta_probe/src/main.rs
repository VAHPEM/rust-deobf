fn main() {
    // touch each dependency so it is linked and leaves registry panic paths
    let re = regex::Regex::new(r"canary::(\w+)").unwrap();
    let hay = "canary::alpha canary::bravo";
    let n = re.find_iter(hay).count();

    let v: serde_json::Value = serde_json::from_str(r#"{"k":[1,2,3]}"#).unwrap();
    let m = v["k"].as_array().map(|a| a.len()).unwrap_or(0);

    let u = url::Url::parse("https://example.com/path?q=1").unwrap();
    let host = u.host_str().unwrap_or("?").to_string();

    use base64::Engine;
    let enc = base64::engine::general_purpose::STANDARD.encode(b"canary");

    println!("{} {} {} {}", n, m, host, enc);
}
