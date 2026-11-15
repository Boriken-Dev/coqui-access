//! A per-user file of pins, in the manner of `~/.ssh/authorized_keys`.
//!
//! The file holds one pin per line, `sha256:<hex>` (a certificate's fingerprint) or
//! `spki-sha256:<hex>` (its public key), then optional whitespace and a comment. Blank lines
//! and lines starting `#` are ignored; a line that is not a pin is skipped and counted. A file
//! may hold [`MAX_PIN_LINES`] lines and be [`MAX_FILE_BYTES`] long.
//!
//! [`AuthorizedFile`] finds the file by a path template, `{home}/.myapp/authorized_certificates`
//! say, with `{home}` (the account's `home` attribute), `{name}` and `{id}` filled from the
//! account a rule already named; it never looks at any other account's file. Who reads the
//! file is a [`PinFileReader`]: the default, [`DirectReader`], opens it and makes the checks
//! sshd makes of `authorized_keys`; a consumer whose process cannot read homes supplies a
//! reader that reads through its own helper, and which makes those checks wherever it has
//! access. The library checks nothing it cannot see: it renders the path, parses the text a
//! reader returns, and turns a refusal into "no pins, and why".

use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use coqui_access::Person;
use coqui_access::guatiao::FromValue;
use coqui_access::guatiao::library::ProviderError;

use super::{PinCheck, PinSet, PinSource, pin_matches};

/// The longest file read, in bytes.
pub const MAX_FILE_BYTES: u64 = 64 * 1024;
/// The most pin lines a file may hold, counting lines that are not valid pins.
pub const MAX_PIN_LINES: usize = 1024;

/// What a reader found at a path.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileRead {
    /// The file's text.
    Text(String),
    /// There is no file: the account keeps no pins here, which is not a complaint.
    Missing,
}

/// Why a reader would not give the file: it counts as no pins and the reason is reported.
/// The reason never holds a pin.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReadFailure(String);

impl ReadFailure {
    /// A refusal for `reason`.
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }

    /// The reason.
    pub fn reason(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ReadFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl core::error::Error for ReadFailure {}

/// Reads the pin file of an account.
///
/// `account` is the candidate person, with `home` and `uid` among its attributes as its
/// directory gave them, and `path` the file as the template rendered it: absolute, with no
/// `..`. The reader makes whatever checks the file deserves where it has access (the owner,
/// who may write it, its parents, symlinks) and reports their result; the library does not
/// repeat them. A file that is not there is [`FileRead::Missing`], not a refusal.
pub trait PinFileReader: Send + Sync {
    /// The text of `path`, or why it may not be used.
    fn read(&self, account: &Person, path: &Path) -> Result<FileRead, ReadFailure>;
}

/// A path template that cannot work. It never quotes the template.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TemplateError;

impl fmt::Display for TemplateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a pin file path is text with {home}, {name} and {id} only")
    }
}

impl core::error::Error for TemplateError {}

enum Part {
    Text(String),
    Home,
    Name,
    Id,
}

/// The pins in a file per user: a [`PinSource`] that reads only the file of the account it
/// is asked about.
pub struct AuthorizedFile {
    template: String,
    parts: Vec<Part>,
    reader: Arc<dyn PinFileReader>,
}

impl fmt::Debug for AuthorizedFile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedFile")
            .field("template", &self.template)
            .finish_non_exhaustive()
    }
}

impl AuthorizedFile {
    /// A source finding the file at `template`, read by [`DirectReader`] until
    /// [`reader`](AuthorizedFile::reader) says otherwise.
    ///
    /// # Errors
    ///
    /// For an empty template, or a `{` that is not `{home}`, `{name}` or `{id}`.
    pub fn new(template: impl Into<String>) -> Result<Self, TemplateError> {
        let template = template.into();
        let mut parts = Vec::new();
        let mut rest = template.as_str();
        while !rest.is_empty() {
            match rest.find(['{', '}']) {
                None => {
                    parts.push(Part::Text(rest.to_owned()));
                    break;
                }
                Some(at) => {
                    if at > 0 {
                        parts.push(Part::Text(rest[..at].to_owned()));
                    }
                    let tail = &rest[at..];
                    let (part, used) = [
                        ("{home}", Part::Home),
                        ("{name}", Part::Name),
                        ("{id}", Part::Id),
                    ]
                    .into_iter()
                    .find(|(word, _)| tail.starts_with(word))
                    .map(|(word, part)| (part, word.len()))
                    .ok_or(TemplateError)?;
                    parts.push(part);
                    rest = &tail[used..];
                }
            }
        }
        if parts.is_empty() {
            return Err(TemplateError);
        }
        Ok(Self {
            template,
            parts,
            reader: Arc::new(DirectReader::new()),
        })
    }

    /// This source reading files through `reader`. Nothing else touches the file system.
    #[must_use]
    pub fn reader(mut self, reader: Arc<dyn PinFileReader>) -> Self {
        self.reader = reader;
        self
    }

    /// The file of `account`, or why there is none to look at.
    fn path_for(&self, account: &Person) -> Result<PathBuf, String> {
        let mut path = String::new();
        for part in &self.parts {
            match part {
                Part::Text(text) => path.push_str(text),
                Part::Home => {
                    let home = text_attribute(account, "home")
                        .ok_or("the account has no home directory")?;
                    if home.is_empty() || home.chars().any(char::is_control) {
                        return Err("the account's home is not a usable path".to_owned());
                    }
                    path.push_str(&home);
                }
                Part::Name => path.push_str(&component(&account.name)?),
                Part::Id => path.push_str(&component(&account.id)?),
            }
        }
        let path = PathBuf::from(path);
        if !(path.is_absolute() || path.to_string_lossy().starts_with('/')) {
            return Err("the pin file's path is not absolute".to_owned());
        }
        if path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err("the pin file's path climbs out with ..".to_owned());
        }
        Ok(path)
    }
}

/// A name or id as one path component, or why not.
fn component(value: &str) -> Result<String, String> {
    let bad = value.is_empty()
        || value == "."
        || value == ".."
        || value
            .chars()
            .any(|c| matches!(c, '/' | '\\') || c.is_control());
    if bad {
        return Err("the account's name is not safe to put in a path".to_owned());
    }
    Ok(value.to_owned())
}

/// An attribute as text, whether the directory gave it as text or as a number.
fn text_attribute(account: &Person, name: &str) -> Option<String> {
    let value = account.attributes.get(name)?;
    String::from_value(value)
        .ok()
        .or_else(|| u64::from_value(value).ok().map(|number| number.to_string()))
}

impl PinSource for AuthorizedFile {
    fn check(&self, person: &Person, pins: &PinSet) -> Result<PinCheck, ProviderError> {
        let path = match self.path_for(person) {
            Ok(path) => path,
            Err(reason) => return Ok(PinCheck::Refused(reason)),
        };
        let text = match self.reader.read(person, &path) {
            Ok(FileRead::Text(text)) => text,
            Ok(FileRead::Missing) => return Ok(PinCheck::Absent),
            Err(failure) => return Ok(PinCheck::Refused(failure.0)),
        };
        Ok(scan(&text, pins))
    }
}

/// Whether `text` holds one of `pins`, skipping what is not a pin and saying how much when
/// nothing is found.
fn scan(text: &str, pins: &PinSet) -> PinCheck {
    let (mut lines, mut skipped, mut held) = (0_usize, 0_usize, false);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        lines += 1;
        if lines > MAX_PIN_LINES {
            return PinCheck::Refused(format!("the file holds more than {MAX_PIN_LINES} lines"));
        }
        let pin = line.split_whitespace().next().unwrap_or_default();
        match pin_matches(pin, pins) {
            Some(found) => held |= found,
            None => skipped += 1,
        }
    }
    if held {
        PinCheck::Holds
    } else if skipped > 0 {
        PinCheck::Refused(format!(
            "{skipped} lines of the file are not pins, and none held"
        ))
    } else {
        PinCheck::Absent
    }
}

/// The longest a [`DirectReader`] waits for the file system by default.
pub const READ_TIMEOUT: Duration = Duration::from_secs(2);
/// The most reads one [`DirectReader`] lets wait on the file system at once by default.
pub const MOST_WAITING: usize = 8;

/// Opens the file itself and makes the checks sshd makes of `authorized_keys`.
///
/// On Unix, from the account's real home down, one component at a time:
///
/// - the path must lie under the account's `home`; no directory on the way and not the file
///   may be a symlink, or on another file system than the home;
/// - the home, every directory below it on the path, and the file must be owned by the
///   account's uid (its `uid` attribute) or by root and must not be writable by group or
///   others;
/// - the file is opened without following a link and without blocking (`O_NOFOLLOW`,
///   `O_NONBLOCK`), and what is read is the opened file, checked again: a regular file, the
///   one the walk saw, of at most [`MAX_FILE_BYTES`].
///
/// The walk and the read run on a thread the reader waits on for [`timeout`]
/// (`READ_TIMEOUT` unless set), so a file system that never answers (a network or FUSE mount,
/// a pipe put where the file should be) costs the caller that long and a refusal. The
/// thread itself stays stuck until the file system answers; a reader lets at most
/// [`max_waiting`](DirectReader::max_waiting) of them wait at once and refuses further reads
/// until some finish.
///
/// There is a gap no portable call closes: a directory above the file may be swapped between
/// the walk and the open by someone who owns it (only the account, or root) and who is not
/// the person being signed in. The checks make the account's own writable paths the only
/// ones that can be abused. Elsewhere than Unix it refuses everything, as those checks have
/// no meaning there.
///
/// [`timeout`]: DirectReader::timeout
#[derive(Debug, Clone)]
#[cfg_attr(
    not(unix),
    allow(dead_code, reason = "only the Unix reader waits on the file system")
)]
pub struct DirectReader {
    timeout: Duration,
    most_waiting: usize,
    waiting: Arc<AtomicUsize>,
}

impl Default for DirectReader {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectReader {
    /// A reader with the default [`READ_TIMEOUT`] and [`MOST_WAITING`].
    pub fn new() -> Self {
        Self {
            timeout: READ_TIMEOUT,
            most_waiting: MOST_WAITING,
            waiting: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// How long one read waits on the file system before it is refused.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// How many reads may be stuck on the file system at once before further ones are
    /// refused without being tried.
    #[must_use]
    pub fn max_waiting(mut self, most: usize) -> Self {
        self.most_waiting = most;
        self
    }
}

impl PinFileReader for DirectReader {
    fn read(&self, account: &Person, path: &Path) -> Result<FileRead, ReadFailure> {
        direct(self, account, path)
    }
}

#[cfg(not(unix))]
fn direct(
    _reader: &DirectReader,
    _account: &Person,
    _path: &Path,
) -> Result<FileRead, ReadFailure> {
    Err(ReadFailure::new(
        "per-user pin files are not supported on this platform",
    ))
}

#[cfg(unix)]
fn direct(reader: &DirectReader, account: &Person, path: &Path) -> Result<FileRead, ReadFailure> {
    let uid: u32 = text_attribute(account, "uid")
        .and_then(|uid| uid.parse().ok())
        .ok_or_else(|| {
            ReadFailure::new("the account has no uid, so a file cannot be trusted as its own")
        })?;
    let home = text_attribute(account, "home")
        .ok_or_else(|| ReadFailure::new("the account has no home directory"))?;
    let path = path.to_path_buf();
    bounded(reader, move || walk_and_read(uid, &home, &path))
}

/// Runs `work` on a thread and waits for it no longer than the reader's timeout.
#[cfg(unix)]
fn bounded<T: Send + 'static>(
    reader: &DirectReader,
    work: impl FnOnce() -> Result<T, ReadFailure> + Send + 'static,
) -> Result<T, ReadFailure> {
    use std::sync::atomic::Ordering;

    if reader.waiting.fetch_add(1, Ordering::SeqCst) >= reader.most_waiting {
        reader.waiting.fetch_sub(1, Ordering::SeqCst);
        return Err(ReadFailure::new(
            "too many pin file reads are stuck on the file system",
        ));
    }
    let (sender, receiver) = std::sync::mpsc::channel();
    let waiting = Arc::clone(&reader.waiting);
    let started = std::thread::Builder::new()
        .name("pin-file-read".to_owned())
        .spawn(move || {
            let result = work();
            waiting.fetch_sub(1, Ordering::SeqCst);
            // The caller may have given up; nobody is left to tell.
            let _ = sender.send(result);
        });
    if started.is_err() {
        reader.waiting.fetch_sub(1, Ordering::SeqCst);
        return Err(ReadFailure::new("a pin file read could not be started"));
    }
    receiver
        .recv_timeout(reader.timeout)
        .unwrap_or_else(|_| Err(ReadFailure::new("reading the pin file timed out")))
}

/// The walk from the home down to the file, and the read of what was opened.
#[cfg(unix)]
fn walk_and_read(uid: u32, home: &str, path: &Path) -> Result<FileRead, ReadFailure> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let trusted = |meta: &std::fs::Metadata, what: &str| -> Result<(), ReadFailure> {
        if meta.uid() != uid && meta.uid() != 0 {
            return Err(ReadFailure::new(format!(
                "the pin file's {what} is owned by someone else"
            )));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(ReadFailure::new(format!(
                "the pin file's {what} is writable by its group or others"
            )));
        }
        Ok(())
    };

    let real_home = std::fs::canonicalize(home)
        .map_err(|_| ReadFailure::new("the account's home cannot be resolved"))?;
    let home_meta = std::fs::metadata(&real_home)
        .map_err(|_| ReadFailure::new("the account's home cannot be examined"))?;
    let relative = path
        .strip_prefix(home)
        .map_err(|_| ReadFailure::new("the pin file is outside the account's home"))?;
    trusted(&home_meta, "directories")?;

    let names: Vec<_> = relative.components().collect();
    if names.is_empty() {
        return Err(ReadFailure::new("the pin file is the account's home"));
    }
    let mut current = real_home;
    let mut seen = None;
    for (index, part) in names.iter().enumerate() {
        let Component::Normal(name) = part else {
            return Err(ReadFailure::new("the pin file's path is not plain names"));
        };
        current.push(name);
        let meta = match std::fs::symlink_metadata(&current) {
            Ok(meta) => meta,
            Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => {
                return Ok(FileRead::Missing);
            }
            Err(_) => return Err(ReadFailure::new("the pin file cannot be examined")),
        };
        if meta.file_type().is_symlink() {
            return Err(ReadFailure::new(
                "the pin file or a directory above it is a symlink",
            ));
        }
        if meta.dev() != home_meta.dev() {
            return Err(ReadFailure::new(
                "the pin file is on another file system than the home",
            ));
        }
        if index + 1 == names.len() {
            if !meta.is_file() {
                return Err(ReadFailure::new("the pin file is not a regular file"));
            }
            seen = Some(meta);
        } else {
            if !meta.is_dir() {
                return Err(ReadFailure::new(
                    "a directory above the pin file is not one",
                ));
            }
            trusted(&meta, "directories")?;
        }
    }
    let seen = seen.ok_or_else(|| ReadFailure::new("the pin file cannot be examined"))?;

    // Without following a link and without waiting on a writer, so a pipe put in place after
    // the walk opens at once and is refused below.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&current)
        .map_err(|_| ReadFailure::new("the pin file cannot be opened"))?;
    // What was opened, not the name that was walked.
    let meta = file
        .metadata()
        .map_err(|_| ReadFailure::new("the pin file cannot be examined"))?;
    if !meta.is_file() {
        return Err(ReadFailure::new("the pin file is not a regular file"));
    }
    if meta.dev() != home_meta.dev() || (meta.dev(), meta.ino()) != (seen.dev(), seen.ino()) {
        return Err(ReadFailure::new(
            "the pin file changed while it was checked",
        ));
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(ReadFailure::new("the pin file is too large"));
    }
    trusted(&meta, "file")?;

    let mut text = String::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|_| ReadFailure::new("the pin file is not text"))?;
    if text.len() as u64 > MAX_FILE_BYTES {
        return Err(ReadFailure::new("the pin file is too large"));
    }
    Ok(FileRead::Text(text))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_read_that_never_answers_is_refused_after_the_timeout_and_counted_until_it_does() {
        let reader = DirectReader::new()
            .timeout(Duration::from_millis(50))
            .max_waiting(1);
        let (release, held) = std::sync::mpsc::channel::<()>();
        let started = std::time::Instant::now();
        let stuck = bounded(&reader, move || {
            let _ = held.recv();
            Ok(())
        });
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(stuck.unwrap_err().reason().contains("timed out"));
        // The stuck read still counts, so a second is refused without being tried.
        let refused = bounded(&reader, || Ok(()));
        assert!(refused.unwrap_err().reason().contains("stuck"));
        // Once it finishes, reads go on.
        release.send(()).unwrap();
        for _ in 0..200 {
            if bounded(&reader, || Ok(())).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the stuck read never freed its place");
    }

    #[test]
    fn a_read_that_answers_in_time_gives_its_result() {
        let reader = DirectReader::new();
        assert_eq!(bounded(&reader, || Ok(7)).unwrap(), 7);
        let refusal = bounded::<()>(&reader, || Err(ReadFailure::new("no")));
        assert_eq!(refusal.unwrap_err().reason(), "no");
    }
}
