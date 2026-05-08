use crate::utils::command::Command;
use crate::{Category, Finding, Severity};
use std::fs;

///  User Information - `su` Bruteforce Test
///  Author: Sangge
///  Last Update: 2025-10-29
///  Description: Attempts to `su` to users with common passwords.
///
///  References:
///  - Based on LinPEAS 6_users_information/18_Brute_su.sh
pub async fn check() -> Option<Finding> {
    let mut finding = Finding::new(
        Category::User,
        Severity::Critical, // Default to Critical if successful
        "`su` Bruteforce Test",
        "Attempts to `su` to users with common passwords.",
    );

    let mut details = Vec::new();

    // use top 200 password
    // from https://nordpass.com/most-common-passwords-list/
    let common_passwords = [
        "123456",
        "123456789",
        "12345678",
        "secret",
        "password",
        "qwerty123",
        "qwerty1",
        "111111",
        "123123",
        "1234567890",
        "qwerty",
        "1234567",
        "11111111",
        "abc123",
        "iloveyou",
        "123123123",
        "000000",
        "00000000",
        "a123456",
        "password1",
        "654321",
        "qwer4321",
        "1q2w3e4r5t",
        "123456a",
        "q1w2e3r4t5y6",
        "987654321",
        "123321",
        "TimeLord12",
        "qwertyuiop",
        "Password",
        "666666",
        "112233",
        "P@ssw0rd",
        "princess",
        "1qaz2wsx3edc",
        "asdfghjkl",
        "88888888",
        "1234561",
        "abcd1234",
        "121212",
        "123456789",
        "1q2w3e4r",
        "monkey",
        "zxcvbnm",
        "a123456789",
        "football",
        "dragon",
        "ashley",
        "baseball",
        "sunshine",
        "soccer",
        "Password1",
        "1qaz2wsx",
        "Aa123456",
        "123qwe",
        "fuckyou",
        "michael",
        "pakistan",
        "superman",
        "Qwerty123",
        "Qwerty12",
        "q1w2e3r4t5y61",
        "aaaaaa",
        "123456789a",
        "asdasd",
        "shadow",
        "555555",
        "123abc",
        "1111111111",
        "123654",
        "jordan",
        "Abcd@1234",
        "qwe123",
        "ABCDEF",
        "killer",
        "qq123456",
        "nicole",
        "12345678910",
        "asdfgh",
        "aa123456",
        "welcome",
        "computer",
        "222222",
        "!ab#cd$",
        "daniel",
        "babygirl",
        "changeme",
        "7777777",
        "basketball",
        "888888",
        "michelle",
        "justin",
        "pokemon",
        "hello",
        "1q2w3e4r5t1",
        "asd123",
        "lovely",
        "purple",
        "hunter",
        "102030",
        "1111111",
        "1234567891",
        "Qwerty123!",
        "qazwsx",
        "master",
        "123456b",
        "anthony",
        "qwer1234",
        "1234qwer",
        "Qwerty1!",
        "b123456",
        "jessica",
        "Qwerty1",
        "Qwerty1234",
        "joshua",
        "andrew",
        "789456123",
        "987654321",
        "11223344",
        "999999",
        "123456c",
        "family",
        "c123456",
        "password123",
        "123456123",
        "loveme",
        "whatever",
        "Daniel73!",
        "jennifer",
        "hannah",
        "summer",
        "1qaz2wsx3edc1",
        "1234567890123",
        "robert",
        "naruto",
        "batman",
        "iloveu",
        "jordan23",
        "12341234",
        "111111111",
        "asdf1234",
        "cookie",
        "matthew",
        "789456",
        "taylor",
        "flower",
        "Abcd1234",
        "pepper",
        "0000000000",
        "amanda",
        "samantha",
        "tigger",
        "12345678Ab@",
        "qwerty12",
        "jasmine",
        "iloveyou1",
        "q1w2e3r4",
        "Welcome@123",
        "1q2w3e",
        "qazWSXedc123",
        "987654",
        "butterfly",
        "charlie",
        "123456d",
        "joseph",
        "87654321",
        "Welcome1",
        "asd123456",
        "peanut",
        "forever",
        "123456",
        "Welcome123",
        "princess1",
        "maggie",
        "d123456",
        "freedom",
        "Samantha1",
        "buster",
        "diamond",
        "Qwerty1?",
        "thomas",
        "brandon",
        "yellow",
        "loveyou",
        "love123",
        "cheese",
        "asshole",
        "123654789",
        "456789",
        "Qwerty123?",
        "starwars",
        "michael1",
        "fuckyou1",
        "mother",
        "777777",
        "chicken",
        "aaaaaaaa",
        "mustang",
        "william",
        "letmein",
    ];

    let mut target_users = Vec::new();
    if let Ok(passwd_content) = fs::read_to_string("/etc/passwd") {
        for line in passwd_content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() > 6
                && (parts[6].ends_with("sh")
                    || parts[6].ends_with("bash")
                    || parts[6].ends_with("zsh"))
            {
                target_users.push(parts[0].to_string());
            }
        }
    }

    if target_users.is_empty() {
        return None;
    }

    details.push("=== `su` Bruteforce Test ===".to_string());
    details.push("Attempting to `su` to users with common passwords...".to_string());

    for user in target_users {
        let user_specific_passwords = ["", user.as_str()];

        let passwords_to_try = user_specific_passwords
            .iter()
            .copied()
            .chain(common_passwords.iter().copied());

        for pwd in passwords_to_try {
            // Skip empty password if not explicitly allowed or if it's just the username
            if pwd.is_empty() && user != "root" {
                // Only try empty for root for now
                continue;
            }

            // Construct the command to pipe password to su
            let command_str = format!("echo '{}' | su {} -c 'whoami'", pwd, user);

            if let Ok(output) = Command::new("sh").arg("-c").arg(&command_str).output()
                && output.status.success()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.trim() == user {
                    details.push(format!(
                        "⚠ CRITICAL: Successfully `su`'d to user '{}' with password '{}'!",
                        user, pwd
                    ));
                    finding.severity = Severity::Critical;
                    finding.details = details;
                    return Some(finding);
                }
            }
        }
    }

    // If no success, return None
    None
}
