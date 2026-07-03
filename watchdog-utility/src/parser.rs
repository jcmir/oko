#[derive(Debug, PartialEq)]
pub enum HeartbeatResult {
    Ok(String),
    Timeout,
    Error(String),
    Eof,
}

pub fn parse_heartbeat(line: &str) -> HeartbeatResult {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return HeartbeatResult::Eof;
    }
    if trimmed.starts_with("HEARTBEAT") {
        HeartbeatResult::Ok(trimmed.to_string())
    } else {
        HeartbeatResult::Error(format!("Unexpected message: {}", trimmed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_heartbeat_valid() {
        let input = "HEARTBEAT 2026-07-03 STATUS:GREEN\n";
        let res = parse_heartbeat(input);
        assert_eq!(
            res,
            HeartbeatResult::Ok("HEARTBEAT 2026-07-03 STATUS:GREEN".to_string())
        );
    }

    #[test]
    fn test_parse_heartbeat_empty() {
        let input = "   \n";
        let res = parse_heartbeat(input);
        assert_eq!(res, HeartbeatResult::Eof);
    }

    #[test]
    fn test_parse_heartbeat_invalid() {
        let input = "SOME OTHER DATA\n";
        let res = parse_heartbeat(input);
        assert_eq!(
            res,
            HeartbeatResult::Error("Unexpected message: SOME OTHER DATA".to_string())
        );
    }
}
