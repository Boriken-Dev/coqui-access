//! A per-user file of pins, in the manner of `~/.ssh/authorized_keys`.
//!
//! The file holds one pin per line, `sha256:<hex>` (a certificate's fingerprint) or
//! `spki-sha256:<hex>` (its public key), then optional whitespace and a comment. Blank lines
//! and lines starting `#` are ignored; a line that is not a pin is skipped and counted. A file
//! may hold [`MAX_PIN_LINES`] lines and be [`MAX_FILE_BYTES`] long.
//!
//! [`AuthorizedFile`] finds the file by a path template, `{home}/.canoa/authorized_certificates`
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
            reader: Arc::new(DirectReader),
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

/// Opens the file itself and makes the checks sshd makes of `authorized_keys`.
///
/// On Unix: the file is not a symlink and is a regular file of at most [`MAX_FILE_BYTES`];
/// its real path is inside the account's real home; the file and every directory from its
/// parent up to and including the home are owned by the account's uid (its `uid` attribute)
/// or by root, and are not writable by group or others. Anything else is a refusal with the
/// reason. Elsewhere it refuses everything, as those checks have no meaning there.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirectReader;

impl PinFileReader for DirectReader {
    fn read(&self, account: &Person, path: &Path) -> Result<FileRead, ReadFailure> {
        direct(account, path)
    }
}

#[cfg(not(unix))]
fn direct(_account: &Person, _path: &Path) -> Result<FileRead, ReadFailure> {
    Err(ReadFailure::new(
        "per-user pin files are not supported on this platform",
    ))
}

#[cfg(unix)]
fn direct(account: &Person, path: &Path) -> Result<FileRead, ReadFailure> {
    use std::io::Read as _;
    use std::os::unix::fs::MetadataExt;

    let uid: u32 = text_attribute(account, "uid")
        .and_then(|uid| uid.parse().ok())
        .ok_or_else(|| {
            ReadFailure::new("the account has no uid, so a file cannot be trusted as its own")
        })?;
    let home = text_attribute(account, "home")
        .ok_or_else(|| ReadFailure::new("the account has no home directory"))?;
    let home = std::fs::canonicalize(&home)
        .map_err(|_| ReadFailure::new("the account's home cannot be resolved"))?;

    let link = match std::fs::symlink_metadata(path) {
        Ok(link) => link,
        Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => {
            return Ok(FileRead::Missing);
        }
        Err(_) => return Err(ReadFailure::new("the pin file cannot be examined")),
    };
    if link.file_type().is_symlink() {
        return Err(ReadFailure::new("the pin file is a symlink"));
    }
    if !link.is_file() {
        return Err(ReadFailure::new("the pin file is not a regular file"));
    }
    let real = std::fs::canonicalize(path)
        .map_err(|_| ReadFailure::new("the pin file's real path cannot be resolved"))?;
    if !real.starts_with(&home) {
        return Err(ReadFailure::new(
            "the pin file is outside the account's home",
        ));
    }

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

    // The opened file is checked, not the name that was: what is read is what was checked.
    let file = std::fs::File::open(&real)
        .map_err(|_| ReadFailure::new("the pin file cannot be opened"))?;
    let meta = file
        .metadata()
        .map_err(|_| ReadFailure::new("the pin file cannot be examined"))?;
    if !meta.is_file() {
        return Err(ReadFailure::new("the pin file is not a regular file"));
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(ReadFailure::new("the pin file is too large"));
    }
    trusted(&meta, "file")?;
    for directory in real.ancestors().skip(1) {
        let meta = std::fs::metadata(directory)
            .map_err(|_| ReadFailure::new("a directory above the pin file cannot be examined"))?;
        trusted(&meta, "directories")?;
        if directory == home {
            break;
        }
    }

    let mut text = String::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|_| ReadFailure::new("the pin file is not text"))?;
    if text.len() as u64 > MAX_FILE_BYTES {
        return Err(ReadFailure::new("the pin file is too large"));
    }
    Ok(FileRead::Text(text))
}
