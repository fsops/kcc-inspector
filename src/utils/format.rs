#![allow(dead_code)]

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    const THRESHOLD: u64 = 1024;

    if bytes == 0 {
        return "0 B".to_string();
    }

    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= THRESHOLD as f64 && unit_index < UNITS.len() - 1 {
        size /= THRESHOLD as f64;
        unit_index += 1;
    }

    format!("{:.1} {}", size, UNITS[unit_index])
}

pub fn format_percentage(value: f64) -> String {
    format!("{:.1}%", value)
}

pub fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else if seconds < 86400 {
        format!("{}h {}m", seconds / 3600, (seconds % 3600) / 60)
    } else {
        format!("{}d {}h", seconds / 86400, (seconds % 86400) / 3600)
    }
}

pub fn format_score_color(score: f64) -> &'static str {
    match score {
        s if s >= 90.0 => "green",
        s if s >= 80.0 => "yellow",
        s if s >= 70.0 => "orange",
        _ => "red",
    }
}

pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    // 只能按 UTF-8 字符边界截断，否则多字节字符（如中文）中间切片会 panic
    let mut end = max_len.saturating_sub(3).min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_string_handles_utf8_boundaries() {
        // 全中文：20 个汉字 = 60 字节，截断到 60 时切片必须落在字符边界上，不能 panic
        let zh = "这是一个很长的中文事件消息用于测试截断是否安全不会崩溃";
        let t = truncate_string(zh, 60);
        assert!(t.ends_with("..."));
        assert!(t.len() <= 60);
        // 短字符串原样返回
        assert_eq!(truncate_string("短", 60), "短");
        // 混合中英文
        let mixed = "abc中文def中文def中文def中文def中文def中文def";
        let t2 = truncate_string(mixed, 30);
        assert!(t2.len() <= 30);
        assert!(t2.ends_with("..."));
        // 边界值：恰好等于 max_len 不截断
        assert_eq!(truncate_string("12345", 5), "12345");
        // 空字符串
        assert_eq!(truncate_string("", 10), "");
    }
}
