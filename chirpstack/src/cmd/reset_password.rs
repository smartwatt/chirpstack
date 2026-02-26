use anyhow::{Context, Result};

use crate::storage::user;

/// Reset a user's password from the command-line.
///
/// This command enables password reset without API access, useful for:
/// - Initial setup of fresh installations
/// - Automated deployment scripts
/// - Recovery from forgotten passwords
///
/// # Arguments
///
/// * `email` - User email address (unique identifier)
/// * `password_file` - Path to file containing the new password
/// * `stdin` - Read password from stdin
pub async fn run(email: &str, password_file: &Option<String>, stdin: bool) -> Result<()> {
    let password = get_password(password_file, stdin).context("Failed to get password")?;

    // Validate password strength (NIST 800-63b guidelines)
    user::validate_password_strength(&password)?;

    // Setup database connection
    crate::storage::setup()
        .await
        .context("Failed to setup storage")?;

    // Reset the password
    let user = user::reset_password_by_email(email, &password)
        .await
        .with_context(|| format!("Failed to reset password for user: {}", email))?;

    println!("Password reset for user: {}", user.email);

    Ok(())
}

fn get_password(password_file: &Option<String>, stdin: bool) -> Result<String> {
    if stdin {
        let input = rpassword::read_password_from_bufread(&mut std::io::stdin().lock())
            .context("Failed to read password from stdin")?;
        return Ok(input);
    }

    if let Some(path) = password_file {
        let pw = std::fs::read_to_string(path.as_str()).context("Failed to read password file")?;
        // Trim only trailing newline/carriage return (common when echo "pass" > file)
        let trimmed = pw.trim_end_matches(&['\n', '\r'][..]);
        return Ok(trimmed.to_string());
    }

    // Interactive prompt
    let password = rpassword::prompt_password("New password: ")?;
    let confirm = rpassword::prompt_password("Confirm password: ")?;

    if password != confirm {
        anyhow::bail!("Passwords do not match");
    }

    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn write_temp_file(contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "chirpstack_test_pw_{}.txt",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }

    #[test]
    fn test_get_password_from_file() {
        let path = write_temp_file("secretpassword\n");
        let pw = get_password(&Some(path.to_str().unwrap().to_string()), false).unwrap();
        fs::remove_file(&path).ok();
        assert_eq!(pw, "secretpassword");
    }

    #[test]
    fn test_get_password_from_file_no_trailing_newline() {
        let path = write_temp_file("secretpassword");
        let pw = get_password(&Some(path.to_str().unwrap().to_string()), false).unwrap();
        fs::remove_file(&path).ok();
        assert_eq!(pw, "secretpassword");
    }

    #[test]
    fn test_get_password_from_file_crlf() {
        let path = write_temp_file("secretpassword\r\n");
        let pw = get_password(&Some(path.to_str().unwrap().to_string()), false).unwrap();
        fs::remove_file(&path).ok();
        assert_eq!(pw, "secretpassword");
    }

    #[test]
    fn test_get_password_file_not_found() {
        let result = get_password(
            &Some("/nonexistent/path/to/password.txt".to_string()),
            false,
        );
        assert!(result.is_err());
    }
}
