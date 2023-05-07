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
}
