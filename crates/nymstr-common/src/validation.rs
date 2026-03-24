//! Input validation for usernames and group IDs.

/// Check if a username is valid: non-empty, max 64 chars, alphanumeric + '-' or '_'.
pub fn is_valid_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= 64
        && username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Check if a group ID is valid: non-empty, max 128 chars, alphanumeric + '-' or '_'.
pub fn is_valid_group_id(group_id: &str) -> bool {
    !group_id.is_empty()
        && group_id.len() <= 128
        && group_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_usernames() {
        assert!(is_valid_username("valid_user123"));
        assert!(is_valid_username("user-name"));
        assert!(is_valid_username("user_name"));
        assert!(is_valid_username("123user"));
        assert!(is_valid_username(&"a".repeat(64)));
    }

    #[test]
    fn test_invalid_usernames() {
        assert!(!is_valid_username(""));
        assert!(!is_valid_username("invalid user"));
        assert!(!is_valid_username("user@domain"));
        assert!(!is_valid_username("user.name"));
        assert!(!is_valid_username(&"a".repeat(65)));
    }

    #[test]
    fn test_valid_group_ids() {
        assert!(is_valid_group_id("valid-group-123"));
        assert!(is_valid_group_id("group_name"));
        assert!(is_valid_group_id(&"a".repeat(128)));
    }

    #[test]
    fn test_invalid_group_ids() {
        assert!(!is_valid_group_id(""));
        assert!(!is_valid_group_id("invalid group"));
        assert!(!is_valid_group_id("group@id"));
        assert!(!is_valid_group_id(&"a".repeat(129)));
    }
}
