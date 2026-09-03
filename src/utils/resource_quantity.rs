//! Parse Kubernetes resource Quantity strings to numeric values for comparison.
//! CPU is parsed to millicores, memory to bytes.

/// Parse CPU quantity string (e.g. "500m", "1") to millicores.
pub fn parse_cpu_str(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(m) = s.strip_suffix('m') {
        if let Ok(n) = m.parse::<i64>() {
            return Some(n);
        }
    }
    if let Ok(n) = s.parse::<f64>() {
        return Some((n * 1000.0) as i64);
    }
    None
}

/// Parse memory quantity string (e.g. "256Mi", "1Gi") to bytes.
pub fn parse_memory_str(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let s = s.replace('i', "");
    let (num_str, unit) = if s.ends_with('K') {
        (s.trim_end_matches('K'), 1024_i64)
    } else if s.ends_with('M') {
        (s.trim_end_matches('M'), 1024 * 1024)
    } else if s.ends_with('G') {
        (s.trim_end_matches('G'), 1024 * 1024 * 1024)
    } else if s.ends_with('T') {
        (s.trim_end_matches('T'), 1024_i64 * 1024 * 1024 * 1024)
    } else if s.ends_with('P') {
        (
            s.trim_end_matches('P'),
            1024_i64 * 1024 * 1024 * 1024 * 1024,
        )
    } else if let Ok(n) = s.parse::<i64>() {
        return Some(n);
    } else {
        return None;
    };
    let n: i64 = num_str.parse().ok()?;
    Some(n * unit)
}
