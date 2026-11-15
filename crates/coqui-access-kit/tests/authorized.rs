//! The per-user pin file: its format, the path it is found at, who reads it, and the
//! sshd-style checks the default reader makes.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use coqui_access::Person;
use coqui_access::guatiao::ToValue;
use coqui_access_kit::pins::{
    AuthorizedFile, FileRead, PinCheck, PinFileReader, PinSet, PinSource, ReadFailure,
};

const FINGERPRINT: &str = "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const KEY: &str = "sha256:ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

fn wanted() -> PinSet {
    let mut pins = PinSet::default();
    pins.fingerprint = Some(FINGERPRINT.to_owned());
    pins.key = Some(KEY.to_owned());
    pins
}

fn only_fingerprint() -> PinSet {
    let mut pins = PinSet::default();
    pins.fingerprint = Some(FINGERPRINT.to_owned());
    pins
}

fn only_key() -> PinSet {
    let mut pins = PinSet::default();
    pins.key = Some(KEY.to_owned());
    pins
}

fn person(name: &str, home: Option<&str>, uid: Option<u32>) -> Person {
    let mut person = Person {
        id: format!("id-{name}"),
        name: name.to_owned(),
        ..Person::default()
    };
    if let Some(home) = home {
        person
            .attributes
            .insert("home".to_owned(), home.to_value().unwrap());
    }
    if let Some(uid) = uid {
        person
            .attributes
            .insert("uid".to_owned(), uid.to_string().to_value().unwrap());
    }
    person
}

fn refused(check: PinCheck) -> String {
    match check {
        PinCheck::Refused(reason) => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A reader that answers from a function and remembers what it was asked.
struct Stand {
    answer: fn(&Person) -> Result<FileRead, ReadFailure>,
    asked: Mutex<Vec<(String, PathBuf)>>,
}

impl Stand {
    fn new(answer: fn(&Person) -> Result<FileRead, ReadFailure>) -> Arc<Self> {
        Arc::new(Self {
            answer,
            asked: Mutex::default(),
        })
    }
}

impl PinFileReader for Stand {
    fn read(&self, account: &Person, path: &Path) -> Result<FileRead, ReadFailure> {
        self.asked
            .lock()
            .unwrap()
            .push((account.name.clone(), path.to_path_buf()));
        (self.answer)(account)
    }
}

#[test]
fn a_reader_supplies_the_text_and_the_library_parses_it() {
    let source = |content: &str| {
        let reader = Arc::new(Fixed(content.to_owned()));
        AuthorizedFile::new("{home}/.keys/authorized")
            .unwrap()
            .reader(reader)
    };
    let alice = person("alice", Some("/home/alice"), Some(1000));

    let both = format!("# pins\n\n  \n{FINGERPRINT}  office laptop\nspki-{KEY}\tsmartcard\n");
    assert_eq!(
        source(&both).check(&alice, &only_fingerprint()).unwrap(),
        PinCheck::Holds
    );
    assert_eq!(
        source(&both).check(&alice, &only_key()).unwrap(),
        PinCheck::Holds
    );

    // A fingerprint line is not a key pin, nor the other way round.
    let swapped = format!("spki-{FINGERPRINT}\n{KEY}\n");
    assert_eq!(
        source(&swapped).check(&alice, &wanted()).unwrap(),
        PinCheck::Absent
    );

    // Any case, CRLF line ends, and a comment after the pin.
    let loud = format!(
        "{}\r\n",
        FINGERPRINT.to_uppercase().replace("SHA256", "sha256")
    );
    assert_eq!(
        source(&loud).check(&alice, &only_fingerprint()).unwrap(),
        PinCheck::Holds
    );

    // Nothing in it, or only comments.
    assert_eq!(
        source("").check(&alice, &wanted()).unwrap(),
        PinCheck::Absent
    );
    assert_eq!(
        source("# only a comment\n")
            .check(&alice, &wanted())
            .unwrap(),
        PinCheck::Absent
    );

    // Lines that are not pins are skipped and counted; a pin still holds past them.
    let mixed = format!("garbage\nsha256:short\n{FINGERPRINT}\n");
    assert_eq!(
        source(&mixed).check(&alice, &only_fingerprint()).unwrap(),
        PinCheck::Holds
    );
    // With none held, the bad lines are the reason.
    let reason = refused(
        source("garbage\nmore garbage\n")
            .check(&alice, &wanted())
            .unwrap(),
    );
    assert!(
        reason.contains('2') && !reason.contains("garbage"),
        "{reason}"
    );
}

struct Fixed(String);

impl PinFileReader for Fixed {
    fn read(&self, _: &Person, _: &Path) -> Result<FileRead, ReadFailure> {
        Ok(FileRead::Text(self.0.clone()))
    }
}

#[test]
fn a_file_with_too_many_pin_lines_is_refused_whole() {
    let lines: String = (0..1025).map(|n| format!("sha256:{n:064x}\n")).collect();
    let source = AuthorizedFile::new("{home}/p")
        .unwrap()
        .reader(Arc::new(Fixed(lines)));
    let alice = person("alice", Some("/home/alice"), Some(1000));
    let reason = refused(source.check(&alice, &only_fingerprint()).unwrap());
    assert!(
        reason.contains("1024") || reason.contains("1 024"),
        "{reason}"
    );
}

#[test]
fn the_path_is_rendered_from_the_account_and_unsafe_ones_never_reach_a_reader() {
    let reader = Stand::new(|_| Ok(FileRead::Missing));
    let source = AuthorizedFile::new("{home}/.myapp/authorized_certificates")
        .unwrap()
        .reader(reader.clone());
    let alice = person("alice", Some("/home/alice"), Some(1000));
    assert_eq!(source.check(&alice, &wanted()).unwrap(), PinCheck::Absent);
    assert_eq!(
        *reader.asked.lock().unwrap(),
        [(
            "alice".to_owned(),
            PathBuf::from("/home/alice/.myapp/authorized_certificates")
        )]
    );

    // `{name}` and `{id}` are one safe component or nothing.
    let by_name = AuthorizedFile::new("/etc/pins/{name}")
        .unwrap()
        .reader(reader.clone());
    for unsafe_name in ["../root", "a/b", "a\\b", "..", ".", "", "nul\0", "a\nb"] {
        let before = reader.asked.lock().unwrap().len();
        let account = person(unsafe_name, Some("/home/x"), Some(1));
        let reason = refused(by_name.check(&account, &wanted()).unwrap());
        assert!(!reason.is_empty());
        assert_eq!(
            reader.asked.lock().unwrap().len(),
            before,
            "{unsafe_name:?}"
        );
    }
    // A plain name is fine.
    let ok = by_name
        .check(&person("bob", None, None), &wanted())
        .unwrap();
    assert_eq!(ok, PinCheck::Absent);

    // No home known, a relative result, a `..` in a home.
    let no_home = person("alice", None, Some(1000));
    assert!(!refused(source.check(&no_home, &wanted()).unwrap()).is_empty());
    let relative = person("alice", Some("home/alice"), Some(1000));
    assert!(!refused(source.check(&relative, &wanted()).unwrap()).is_empty());
    let climbing = person("alice", Some("/home/alice/../root"), Some(1000));
    assert!(!refused(source.check(&climbing, &wanted()).unwrap()).is_empty());

    // The template is checked when it is made.
    for bad in ["", "{unknown}/x", "{home", "{home}}"] {
        assert!(AuthorizedFile::new(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn only_the_reader_is_consulted_when_one_is_given() {
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().join("alice");
    std::fs::create_dir_all(home.join(".k")).unwrap();
    std::fs::write(home.join(".k/p"), format!("{FINGERPRINT}\n")).unwrap();
    let alice = person("alice", Some(home.to_str().unwrap()), Some(1));
    // The file on disk holds the pin; the reader says there is no file; the reader wins.
    let reader = Stand::new(|_| Ok(FileRead::Missing));
    let source = AuthorizedFile::new("{home}/.k/p")
        .unwrap()
        .reader(reader.clone());
    assert_eq!(
        source.check(&alice, &only_fingerprint()).unwrap(),
        PinCheck::Absent
    );
    assert_eq!(reader.asked.lock().unwrap().len(), 1);
}

#[test]
fn a_reader_gives_text_for_one_user_and_a_refusal_for_another() {
    let reader = Stand::new(|account| {
        if account.name == "alice" {
            Ok(FileRead::Text(format!("{FINGERPRINT} alice\n")))
        } else {
            Err(ReadFailure::new("the helper cannot trust that file"))
        }
    });
    let source = AuthorizedFile::new("{home}/p").unwrap().reader(reader);
    let alice = person("alice", Some("/home/alice"), Some(1000));
    let bob = person("bob", Some("/home/bob"), Some(1001));
    assert_eq!(
        source.check(&alice, &only_fingerprint()).unwrap(),
        PinCheck::Holds
    );
    assert_eq!(
        refused(source.check(&bob, &only_fingerprint()).unwrap()),
        "the helper cannot trust that file"
    );
}

#[cfg(unix)]
mod direct {
    //! The default reader, on real files.

    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    use super::*;

    /// A home with `.k/p` holding `content`: home 0700, `.k` 0700, file 0600.
    struct Home {
        _directory: tempfile::TempDir,
        home: PathBuf,
        uid: u32,
    }

    impl Home {
        fn new(name: &str, content: &str) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let home = directory.path().join(name);
            std::fs::create_dir_all(home.join(".k")).unwrap();
            std::fs::write(home.join(".k/p"), content).unwrap();
            let uid = std::fs::metadata(&home).unwrap().uid();
            assert_ne!(uid, 0, "run these tests as an ordinary user, not root");
            let this = Self {
                _directory: directory,
                home,
                uid,
            };
            this.mode(&this.home, 0o700);
            this.mode(&this.home.join(".k"), 0o700);
            this.mode(&this.home.join(".k/p"), 0o600);
            this
        }

        fn mode(&self, path: &Path, mode: u32) {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }

        fn account(&self) -> Person {
            let name = self.home.file_name().unwrap().to_str().unwrap();
            person(name, Some(self.home.to_str().unwrap()), Some(self.uid))
        }

        fn check(&self) -> PinCheck {
            AuthorizedFile::new("{home}/.k/p")
                .unwrap()
                .check(&self.account(), &only_fingerprint())
                .unwrap()
        }
    }

    fn pin() -> String {
        format!("{FINGERPRINT} laptop\n")
    }

    #[test]
    fn a_file_the_user_owns_and_only_the_user_can_write_is_read() {
        let home = Home::new("alice", &pin());
        assert_eq!(home.check(), PinCheck::Holds);
        // Readable by the group is fine: only writing is a way in.
        home.mode(&home.home.join(".k/p"), 0o640);
        assert_eq!(home.check(), PinCheck::Holds);
    }

    #[test]
    fn a_missing_file_is_no_pins_without_a_complaint() {
        let home = Home::new("alice", &pin());
        std::fs::remove_file(home.home.join(".k/p")).unwrap();
        assert_eq!(home.check(), PinCheck::Absent);
    }

    #[test]
    fn a_file_writable_by_group_or_others_is_no_pins_with_a_reason() {
        for mode in [0o620, 0o602, 0o660, 0o666, 0o664] {
            let home = Home::new("alice", &pin());
            home.mode(&home.home.join(".k/p"), mode);
            let reason = refused(home.check());
            assert!(reason.contains("writable"), "{mode:o}: {reason}");
        }
    }

    #[test]
    fn a_parent_directory_writable_by_group_or_others_is_no_pins_with_a_reason() {
        for mode in [0o770, 0o707, 0o777] {
            let home = Home::new("alice", &pin());
            home.mode(&home.home.join(".k"), mode);
            assert!(refused(home.check()).contains("writable"), "{mode:o} on .k");
            let home = Home::new("alice", &pin());
            home.mode(&home.home, mode);
            assert!(
                refused(home.check()).contains("writable"),
                "{mode:o} on the home"
            );
        }
    }

    #[test]
    fn a_file_or_directory_owned_by_someone_else_is_no_pins_with_a_reason() {
        let home = Home::new("alice", &pin());
        let mut account = home.account();
        // The account claims to be another uid: the files are not its own.
        account.attributes.insert(
            "uid".to_owned(),
            (home.uid + 1).to_string().to_value().unwrap(),
        );
        let check = AuthorizedFile::new("{home}/.k/p")
            .unwrap()
            .check(&account, &only_fingerprint())
            .unwrap();
        assert!(refused(check).contains("owned"));
    }

    #[test]
    fn a_symlink_for_the_file_is_no_pins_with_a_reason() {
        let home = Home::new("alice", &pin());
        std::fs::write(home.home.join("real"), pin()).unwrap();
        home.mode(&home.home.join("real"), 0o600);
        std::fs::remove_file(home.home.join(".k/p")).unwrap();
        symlink(home.home.join("real"), home.home.join(".k/p")).unwrap();
        assert!(refused(home.check()).contains("symlink"));
    }

    #[test]
    fn a_symlinked_parent_that_leaves_the_home_is_no_pins_with_a_reason() {
        let home = Home::new("alice", "");
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(outside.path().join("k")).unwrap();
        std::fs::write(outside.path().join("k/p"), pin()).unwrap();
        for path in [outside.path().to_path_buf(), outside.path().join("k")] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::set_permissions(
            outside.path().join("k/p"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::fs::remove_dir_all(home.home.join(".k")).unwrap();
        symlink(outside.path().join("k"), home.home.join(".k")).unwrap();
        let reason = refused(home.check());
        assert!(reason.contains("symlink"), "{reason}");
    }

    #[test]
    fn a_symlinked_parent_is_refused_even_when_it_stays_inside_the_home() {
        let home = Home::new("alice", &pin());
        std::fs::rename(home.home.join(".k"), home.home.join("real_k")).unwrap();
        symlink(home.home.join("real_k"), home.home.join(".k")).unwrap();
        assert!(refused(home.check()).contains("symlink"));
    }

    #[test]
    fn a_pipe_put_where_the_file_should_be_is_refused_at_once() {
        let home = Home::new("alice", &pin());
        std::fs::remove_file(home.home.join(".k/p")).unwrap();
        let made = std::process::Command::new("mkfifo")
            .arg(home.home.join(".k/p"))
            .status()
            .expect("mkfifo runs");
        assert!(made.success());
        home.mode(&home.home.join(".k/p"), 0o600);
        // A blocking open of a pipe with no writer waits forever; the check must not.
        let (sender, receiver) = std::sync::mpsc::channel();
        let asking = std::thread::spawn(move || {
            let _ = sender.send(refused(home.check()));
        });
        let reason = receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the check came back");
        asking.join().unwrap();
        assert!(reason.contains("regular"), "{reason}");
    }

    #[test]
    fn the_file_is_opened_without_following_a_link_swapped_in_after_the_walk() {
        // The walk sees a regular file; a link replaces it before the open. Simulated by the
        // reader being asked about a path whose last component is a link: it is refused as one.
        let home = Home::new("alice", &pin());
        std::fs::write(home.home.join("other"), pin()).unwrap();
        home.mode(&home.home.join("other"), 0o600);
        std::fs::remove_file(home.home.join(".k/p")).unwrap();
        symlink(home.home.join("other"), home.home.join(".k/p")).unwrap();
        assert!(refused(home.check()).contains("symlink"));
    }

    #[test]
    fn something_that_is_not_a_regular_file_or_is_too_large_is_no_pins_with_a_reason() {
        let home = Home::new("alice", &pin());
        std::fs::remove_file(home.home.join(".k/p")).unwrap();
        std::fs::create_dir(home.home.join(".k/p")).unwrap();
        assert!(refused(home.check()).contains("regular"));

        let home = Home::new("alice", &pin());
        let big = format!("# {}\n{}", "x".repeat(70_000), pin());
        std::fs::write(home.home.join(".k/p"), big).unwrap();
        assert!(refused(home.check()).contains("large"));
    }

    #[test]
    fn a_missing_uid_or_home_is_no_pins_with_a_reason() {
        let home = Home::new("alice", &pin());
        let source = AuthorizedFile::new("{home}/.k/p").unwrap();
        let mut no_uid = home.account();
        no_uid.attributes.remove("uid");
        assert!(refused(source.check(&no_uid, &only_fingerprint()).unwrap()).contains("uid"));
        let missing_home = person("alice", Some("/nonexistent/home/alice"), Some(home.uid));
        assert!(!refused(source.check(&missing_home, &only_fingerprint()).unwrap()).is_empty());
    }

    #[test]
    fn a_pin_is_found_only_in_the_right_users_file() {
        let alice = Home::new("alice", &pin());
        let bob = Home::new("bob", "# nothing for me\n");
        let source = AuthorizedFile::new("{home}/.k/p").unwrap();
        assert_eq!(
            source.check(&alice.account(), &only_fingerprint()).unwrap(),
            PinCheck::Holds
        );
        assert_eq!(
            source.check(&bob.account(), &only_fingerprint()).unwrap(),
            PinCheck::Absent
        );
    }
}

// ---- through the matcher, and the global table -------------------------------------------

mod matched {
    use coqui_access::guatiao::library::ProviderError;
    use coqui_access::{Claims, Directory, Lookup};
    use coqui_access_kit::MemoryTable;
    use coqui_access_kit::matcher::{Match, MatchRule, Matcher, MatcherConfig};
    use coqui_access_kit::pins::{AccountPin, TablePins};

    use super::*;

    struct People;

    impl Directory for People {
        fn lookup(&self, lookup: Lookup) -> Result<Option<Person>, ProviderError> {
            Ok(["alice", "bob"].contains(&lookup.value.as_str()).then(|| {
                person(
                    &lookup.value,
                    Some(&format!("/home/{}", lookup.value)),
                    Some(1),
                )
            }))
        }
    }

    fn certificate_for(name: &str) -> Lookup {
        let mut claims = Claims::default();
        claims
            .values
            .insert("subject.cn".to_owned(), vec![name.to_owned()]);
        claims
            .values
            .insert("fingerprint".to_owned(), vec![FINGERPRINT.to_owned()]);
        Lookup {
            by: "claims".to_owned(),
            value: "label".to_owned(),
            claims: Some(claims),
        }
    }

    fn matcher(source: Arc<dyn PinSource>) -> Matcher {
        let mut config = MatcherConfig::default();
        config.rule = vec![MatchRule::new("name", "{subject.cn}").pins("files")];
        Matcher::builder(config)
            .pin_source("files", source)
            .build()
            .unwrap()
    }

    #[test]
    fn a_pin_in_alices_file_logs_alice_in_and_never_a_certificate_that_names_bob() {
        // Only alice's file holds the pin; bob's does not exist.
        let reader = Stand::new(|account| {
            if account.name == "alice" {
                Ok(FileRead::Text(format!("{FINGERPRINT}\n")))
            } else {
                Ok(FileRead::Missing)
            }
        });
        let files = Arc::new(
            AuthorizedFile::new("{home}/.myapp/authorized_certificates")
                .unwrap()
                .reader(reader.clone()),
        );
        let matcher = matcher(files);
        let alice = matcher.resolve(&certificate_for("alice"), &People).unwrap();
        assert!(matches!(alice.result, Match::Found(found) if found.name == "alice"));
        let bob = matcher.resolve(&certificate_for("bob"), &People).unwrap();
        assert!(matches!(bob.result, Match::NotFound));
        // Each time only the named account's file was asked for, never a scan.
        let asked: Vec<String> = reader
            .asked
            .lock()
            .unwrap()
            .iter()
            .map(|(name, _)| name.clone())
            .collect();
        assert_eq!(asked, ["alice", "bob"]);
    }

    #[test]
    fn the_global_table_is_a_source_by_the_same_trait() {
        let table = Arc::new(MemoryTable::from_records([
            AccountPin::new(
                "alice",
                FINGERPRINT.to_uppercase().replace("SHA256", "sha256"),
            ),
            AccountPin::new("bob", format!("spki-{KEY}")),
        ]));
        let source = Arc::new(TablePins::new(table).unwrap());
        let matcher = matcher(source.clone());
        let alice = matcher.resolve(&certificate_for("alice"), &People).unwrap();
        assert!(matches!(alice.result, Match::Found(_)));
        // Bob's pin is a different one: not the certificate presented.
        let bob = matcher.resolve(&certificate_for("bob"), &People).unwrap();
        assert!(matches!(bob.result, Match::NotFound));
        assert_eq!(
            source
                .check(&person("bob", None, None), &only_key())
                .unwrap(),
            PinCheck::Holds
        );
        let junk = Arc::new(MemoryTable::from_records([AccountPin::new(
            "alice", "nonsense",
        )]));
        assert!(TablePins::new(junk).is_err());
    }
}
