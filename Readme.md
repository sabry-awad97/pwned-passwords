# Pwned Passwords Checker

This command-line program checks whether passwords have been compromised in data breaches using the [Have I Been Pwned](https://haveibeenpwned.com/) public API or a local compromised password database. It also includes a password strength checker that analyzes the strength of a given password based on several criteria and returns a score indicating how strong the password is.

## 🚀 Installation

To use this program, you will need to have Rust installed on your system. See [here](https://www.rust-lang.org/tools/install) for instructions on how to install Rust.

Once Rust is installed, you can download and build the program by cloning this repository and running the following command:

```sh
cargo build --release
```

The built binary will be located in the `target/release/` directory.

## 🛠 Usage

The program can be run from the command line using the following syntax:

```sh
pwned-passwords [OPTIONS] <passwords>...
```

where `<passwords>` is a list of passwords to check.
Each password should be provided as a separate command-line argument.

The program supports the following options:

- `--strength`: check password strength (default: false)
- `--local-db PATH`: path to a local compromised password database file (default: none)

### Example Usage

```sh
pwned-passwords --strength "password123" "correct horse battery staple" --local-db "path/to/database.txt"
```

This command will check the passwords "password123" and "correct horse battery staple" for compromise using the local compromised password database at "path/to/database.txt". It will also check their strength and return a score indicating their relative strength.

## 🔒 Password Strength

The password strength checker included in this program analyzes the strength of a given password based on several criteria, including:

- **Length:** The longer the password, the stronger it is.
- **Complexity:** Passwords that include a combination of upper- and lowercase letters, numbers, and symbols are stronger than those that do not.
- **Uniqueness:** Passwords that are unique and not found in data breaches are stronger than those that have been compromised.

The password strength checker returns a score between 0 and 5 indicating the strength of the password based on these criteria. A score of 0 indicates a very weak password, while a score of 5 indicates a very strong password.

If the `--strength` option is used when running the program, the password strength score will be printed along with the check result. If the score is below a certain threshold (in this case, 3), the program will advise the user to choose a stronger password.

## 📁 Local Compromised Password Database

In addition to using the online "Have I Been Pwned" API, the program also supports loading a local compromised password database from a file. This can be useful in situations where network connectivity is limited or when there is a need for additional security by not querying an external API.

The local database file should contain a list of password hashes and the number of times that password has been found in a data breach, separated by a colon (":"). The hash should be in SHA-1 format, represented as a 40-digit hexadecimal number.

For example:

```sh
005D0E6F8F9EA98F1A1E2F45C4328F69A176:32
00FD60FABDDB6E733F7A474F6A50ED7D9461:1
018E250F97CF178F3F3CAE29F8F7B707311A:349
```

The program will use the first 5 characters of the SHA-1 hash of the password being checked to look up matching hashes in the database. If a match is found, it will check the remaining characters of the hash to see if the password has been found in a data breach.

If the `--local-db` option is used when running the program, the program will use the specified file as the local compromised password database instead of querying the "Have I Been Pwned" API.

## 👏 Dependencies

- [futures](https://crates.io/crates/futures) - Concurrency primitives for Rust
- [reqwest](https://crates.io/crates/reqwest) - HTTP client for Rust
- [sha1](https://crates.io/crates/sha1) - SHA-1 hashing algorithm for Rust
- [structopt](https://crates.io/crates/structopt) - command-line argument parser for Rust
- [tokio](https://crates.io/crates/tokio) - asynchronous runtime for Rust

## 🤝 Contributing

Thank you for considering contributing to `pwned-passwords`! Follow these steps to contribute:

1. Fork this repository and clone it to your local machine.
2. Create a new branch for your changes: `git checkout -b my-feature-branch`.
3. Make your changes and ensure that the tests pass: `cargo test`.
4. Commit your changes with a descriptive commit message: `git commit -m "feat: Add new feature"`.
5. Push your changes to the remote branch: `git push origin my-feature-branch`.
6. Create a new pull request and describe your changes.

When submitting a pull request, please include a detailed description of the changes you made, along with any relevant code comments or documentation. Additionally, please make sure that your changes are fully tested and do not break any existing functionality.

To run the test suite, you can use the following command:

```sh
cargo test
```

This command will run all unit tests in the project and report any failures or errors.

## License

This program is licensed under the [MIT License](https://opensource.org/licenses/MIT). Feel free to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of this program, subject to the conditions of the license.

## Acknowledgments

This program was inspired by the [Have I Been Pwned](https://haveibeenpwned.com/) project and uses the [reqwest](https://github.com/seanmonstar/reqwest) and [sha1](https://github.com/RustCrypto/hashes/tree/master/sha1) Rust crates.

Additionally, credit is due to the following contributors to this project:

- Sabry Awad - (added password strength checker - added local compromised password database support - improved error handling and testing)

## Contact

If you have any questions or issues with this program, feel free to contact the author at dr.sabry1997@gmail.com.
