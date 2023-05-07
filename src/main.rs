use std::{
    fs::File,
    io::{BufRead, BufReader},
};

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

    #[structopt(short, long, help = "Check password strength")]
    strength: bool,

    #[structopt(
        short,
        long,
        help = "Path to a local compromised password database file"
    )]
    local_db: Option<String>,
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
    score: Option<u32>,
}

struct PasswordChecker;

#[derive(Debug)]
enum PasswordError {
    RequestError(reqwest::Error),
    ResponseError(reqwest::Error),
    FileError(std::io::Error),
    DatabaseError(String),
}

impl From<reqwest::Error> for PasswordError {
    fn from(error: reqwest::Error) -> Self {
        PasswordError::RequestError(error)
    }
}

impl From<std::io::Error> for PasswordError {
    fn from(error: std::io::Error) -> Self {
        PasswordError::FileError(error)
    }
}

impl std::error::Error for PasswordError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PasswordError::RequestError(error) => Some(error),
            PasswordError::ResponseError(error) => Some(error),
            PasswordError::FileError(error) => Some(error),
            PasswordError::DatabaseError(_) => None,
        }
    }

    fn description(&self) -> &str {
        match self {
            PasswordError::RequestError(_) => "Error sending request",
            PasswordError::ResponseError(_) => "Error receiving response",
            PasswordError::FileError(_) => "Error reading file",
            PasswordError::DatabaseError(message) => message,
        }
    }
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordError::RequestError(error) => write!(f, "Error sending request: {}", error),
            PasswordError::ResponseError(error) => write!(f, "Error receiving response: {}", error),
            PasswordError::FileError(error) => write!(f, "Error reading file: {}", error),
            PasswordError::DatabaseError(message) => write!(f, "{}", message),
        }
    }
}

impl PasswordChecker {
    fn hash_password(password: &str) -> String {
        let mut hasher = sha1::Sha1::new();
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();
        hash.iter()
            .map(|b| format!("{:02x}", b).to_uppercase())
            .collect()
    }

    fn load_local_database(path: &str) -> Result<Vec<String>, PasswordError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        reader
            .lines()
            .map(|line| {
                line.map_err(|error| {
                    PasswordError::DatabaseError(format!("Failed to read line: {}", error))
                })
            })
            .collect()
    }

    async fn check_password(
        password: &str,
        local_db: Option<&Vec<String>>,
    ) -> Result<PasswordCheckResult, PasswordError> {
        let password_hash = Self::hash_password(password);
        let compromised_count: u32 = if let Some(db) = local_db {
            db.iter()
                .filter(|hash| hash.starts_with(&password_hash[..5]))
                .fold(0, |count, hash| {
                    if hash == &password_hash[..] {
                        count
                            + hash
                                .split(':')
                                .nth(1)
                                .expect("Failed to parse count")
                                .parse::<u32>()
                                .expect("Failed to convert count")
                    } else {
                        count
                    }
                })
        } else {
            let request_url = format!(
                "https://api.pwnedpasswords.com/range/{}",
                &password_hash[0..5]
            );
            let client = reqwest::Client::new();
            let response = client
                .get(&request_url)
                .send()
                .await
                .map_err(|error| PasswordError::RequestError(error))?
                .text()
                .await
                .map_err(|error| PasswordError::ResponseError(error))?;

            let suffix = &password_hash[5..];
            response
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
                })
        };

        let score = if compromised_count == 0 {
            Some(Self::score_password(password))
        } else {
            None
        };

        Ok(PasswordCheckResult {
            password: password.to_string(),
            status: PasswordStatus::from_count(compromised_count),
            score,
        })
    }

    fn score_password(password: &str) -> u32 {
        let mut score = 0;

        if password.chars().count() >= 8 {
            score += 1;
        }
        if password.chars().any(|c| c.is_uppercase()) {
            score += 1;
        }
        if password.chars().any(|c| c.is_lowercase()) {
            score += 1;
        }
        if password.chars().any(|c| c.is_numeric()) {
            score += 1;
        }
        if password.chars().any(|c| !c.is_alphanumeric()) {
            score += 1;
        }

        score
    }

    async fn check_passwords(
        passwords: &[String],
        local_db: Option<&Vec<String>>,
    ) -> Result<Vec<PasswordCheckResult>, PasswordError> {
        let futures: Vec<_> = passwords
            .iter()
            .map(|password| Self::check_password(password, local_db))
            .collect();
        futures::future::join_all(futures)
            .await
            .into_iter()
            .collect()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::from_args();
    let local_db = match args.local_db {
        Some(path) => {
            let hashes = PasswordChecker::load_local_database(&path)?;
            println!(
                "Loaded {} hashes from the local database at {}",
                hashes.len(),
                path
            );
            Some(hashes)
        }
        None => None,
    };
    let results = PasswordChecker::check_passwords(&args.passwords, local_db.as_ref()).await?;
    for result in results {
        match result.status {
            PasswordStatus::Compromised(count) => {
                println!(
                    "The password '{}' was found in {} data breaches. Please consider using a different password.",
                    result.password,
                    count
                );
            }
            PasswordStatus::Safe => {
                println!(
                    "The password '{}' has not been found in any known data breaches. Good job!",
                    result.password
                );
            }
        }

        if args.strength {
            if let Some(score) = result.score {
                println!(
                    "The password strength score for '{}' is {}.",
                    result.password, score
                );
                if score < 3 {
                    println!("The password strength is weak. Please consider choosing a stronger password.");
                }
            } else {
                println!("Cannot check password strength for password '{}' because it was found in a breach.", result.password);
            }
        }
    }
    Ok(())
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
        let result = PasswordChecker::check_password("password123", None)
            .await
            .unwrap();
        assert_eq!(result.password, "password123");
        assert_eq!(result.status, PasswordStatus::Compromised(251682));
    }

    #[tokio::test]
    async fn test_check_password_safe() {
        let result = PasswordChecker::check_password("very_strong_password#123", None)
            .await
            .unwrap();
        assert_eq!(result.password, "very_strong_password#123");
        assert_eq!(result.status, PasswordStatus::Safe);
    }

    #[test]
    fn test_password_status_from_count_safe() {
        let status = PasswordStatus::from_count(0);
        assert_eq!(status, PasswordStatus::Safe);
    }

    #[test]
    fn test_password_status_from_count_compromised() {
        let status = PasswordStatus::from_count(12345);
        assert_eq!(status, PasswordStatus::Compromised(12345));
    }

    #[tokio::test]
    async fn test_check_passwords() {
        let passwords = vec![
            "very_strong_password#123".to_string(),
            "password123".to_string(),
        ];
        let results = PasswordChecker::check_passwords(&passwords, None)
            .await
            .unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].password, "very_strong_password#123");
        assert_eq!(results[0].status, PasswordStatus::Safe);
        assert_eq!(results[1].password, "password123");
        assert_eq!(results[1].status, PasswordStatus::Compromised(251682));
    }

    #[test]
    fn test_score_password() {
        assert_eq!(PasswordChecker::score_password("password"), 2);
        assert_eq!(PasswordChecker::score_password("Password"), 3);
        assert_eq!(PasswordChecker::score_password("Password1"), 4);
        assert_eq!(PasswordChecker::score_password("Password1!"), 5);
        assert_eq!(PasswordChecker::score_password("12345678"), 2);
        assert_eq!(PasswordChecker::score_password("1234567a"), 3);
        assert_eq!(PasswordChecker::score_password("1234567A"), 3);
        assert_eq!(PasswordChecker::score_password("1234567A!"), 4);
        assert_eq!(PasswordChecker::score_password("!@#$%^&*"), 2);
        assert_eq!(PasswordChecker::score_password("!@#$%^&*a"), 3);
        assert_eq!(PasswordChecker::score_password("!@#$%^&*A"), 3);
        assert_eq!(PasswordChecker::score_password("!@#$%^&*1"), 3);
        assert_eq!(PasswordChecker::score_password("!@#$%^&*A1"), 4);
        assert_eq!(PasswordChecker::score_password("!@#$%^&*A1a"), 5);
    }

    #[test]
    fn test_load_local_database() {
        let result = PasswordChecker::load_local_database("tests/test_db.txt");
        assert!(result.is_ok());
        let db = result.unwrap();
        assert_eq!(db.len(), 2);
        assert_eq!(db[0], "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:1");
        assert_eq!(db[1], "7C4A8D09CA3762AF61E59520943DC26494F8941B:2");
    }
}
