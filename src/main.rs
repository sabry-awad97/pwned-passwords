use sha1::Digest;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "pwned-passwords",
    about = "Checks whether passwords have been compromised in data breaches."
)]
struct Cli {
    #[structopt(
        name = "passwords",
        required = true,
        min_values = 1,
        help = "Passwords to check"
    )]
    passwords: Vec<String>,
}

#[derive(Debug, PartialEq)]
enum PasswordStatus {
    Compromised(u32),
    Safe,
}

impl PasswordStatus {
    fn from_count(count: u32) -> PasswordStatus {
        if count > 0 {
            PasswordStatus::Compromised(count)
        } else {
            PasswordStatus::Safe
        }
    }
}

#[derive(Debug)]
struct PasswordCheckResult {
    password: String,
    status: PasswordStatus,
}

struct PasswordChecker;

impl PasswordChecker {
    fn hash_password(password: &str) -> String {
        let mut hasher = sha1::Sha1::new();
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();
        hash.iter()
            .map(|b| format!("{:02x}", b).to_uppercase())
            .collect()
    }

    async fn check_password(
        password: &str,
    ) -> Result<PasswordCheckResult, Box<dyn std::error::Error>> {
        let password_hash = Self::hash_password(password);
        let request_url = format!(
            "https://api.pwnedpasswords.com/range/{}",
            &password_hash[0..5]
        );
        let client = reqwest::Client::new();
        let response = client.get(&request_url).send().await?.text().await?;

        let suffix = &password_hash[5..];
        let compromised_count: u32 = response
            .lines()
            .filter(|line| line.starts_with(suffix))
            .fold(0, |count, line| {
                if line.starts_with(suffix) {
                    count
                        + line
                            .split(':')
                            .nth(1)
                            .expect("Failed to parse count")
                            .parse::<u32>()
                            .expect("Failed to convert count")
                } else {
                    count
                }
            });
        Ok(PasswordCheckResult {
            password: password.to_string(),
            status: PasswordStatus::from_count(compromised_count),
        })
    }
}

fn main() {
    let args = Cli::from_args();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_password() {
        let password = "password123";
        let expected_hash = "CBFDAC6008F9CAB4083784CBD1874F76618D2A97";
        let actual_hash = PasswordChecker::hash_password(password);
        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn test_hash_password_empty() {
        let password = "";
        let expected_hash = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709";
        let actual_hash = PasswordChecker::hash_password(password);
        assert_eq!(actual_hash, expected_hash);
    }

    #[test]
    fn test_hash_password_unicode() {
        let password = "こんにちは";
        let expected_hash = "20427A708C3F6F07CF12AB23557982D9E6D23B61";
        let actual_hash = PasswordChecker::hash_password(password);
        assert_eq!(actual_hash, expected_hash);
    }

    #[tokio::test]
    async fn test_check_password_compromised() {
        let result = PasswordChecker::check_password("password123")
            .await
            .unwrap();
        assert_eq!(result.password, "password123");
        assert_eq!(result.status, PasswordStatus::Compromised(251682));
    }

    #[tokio::test]
    async fn test_check_password_safe() {
        let result = PasswordChecker::check_password("very_strong_password#123")
            .await
            .unwrap();
        assert_eq!(result.password, "very_strong_password#123");
        assert_eq!(result.status, PasswordStatus::Safe);
    }
}
