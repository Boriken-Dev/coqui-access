//! What the access plugins share. Not a library API: a plugin is a deployable, so it is where
//! a storage format is chosen.
//!
//! A plugin's Guatiao config names where its records come from in a `source` object that holds
//! exactly one source kind:
//!
//! ```json
//! { "source": { "file": { "path": "accounts.toml", "format": "toml" } } }
//! ```
//!
//! `file` is the only kind implemented. The object is open to more (a SQL database, an HTTP
//! API) without changing the plugins' other options. With no `source`, records live in memory.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

use std::fmt;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use coqui_access::error;
use coqui_access::guatiao::library::ProviderError;
use coqui_access::guatiao::{FromValue, Schema, ToValue};
use coqui_access_kit::file::{self, Stamp};
use coqui_access_kit::{Argon2Params, Keyed, MemoryTable, Revision, Snapshot, SourceError, Table};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// The most a table file may hold, in bytes.
pub const MAX_TABLE_BYTES: usize = 1024 * 1024;

/// How a file source encodes its records.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao, rename_all = "lowercase")]
pub enum Format {
    /// A TOML document with one array of tables named for the plugin's records.
    #[default]
    Toml,
}

/// A table kept in one private file.
#[derive(Debug, Clone, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao)]
pub struct FileSource {
    /// The file. Created, readable by its owner alone, when the first record is put; a
    /// missing file is an empty table.
    pub path: String,
    /// How the file is encoded. Default `toml`.
    #[map(default)]
    pub format: Format,
}

/// Where a plugin's records come from. Exactly one member is set.
#[derive(Debug, Clone, Default, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao)]
pub struct SourceConfig {
    /// Records in a file.
    pub file: Option<FileSource>,
}

impl SourceConfig {
    /// A source kept in the TOML file at `path`.
    pub fn toml_file(path: impl Into<String>) -> Self {
        Self {
            file: Some(FileSource {
                path: path.into(),
                format: Format::Toml,
            }),
        }
    }

    /// The same kind of source beside this one, for a second table: a file source becomes
    /// the file named `<path>.<suffix>`.
    pub fn sibling(&self, suffix: &str) -> Self {
        Self {
            file: self.file.as_ref().map(|file| FileSource {
                path: format!("{}.{suffix}", file.path),
                format: file.format,
            }),
        }
    }
}

/// The table a plugin reads `section` records from: the one `source` names, or an empty
/// table in memory when there is none.
///
/// # Errors
///
/// A bad-value error when `source` names no source kind or a file with an empty path.
pub fn open_table<T>(
    source: Option<&SourceConfig>,
    section: &'static str,
) -> Result<Arc<dyn Table<T>>, ProviderError>
where
    T: Keyed + Clone + Send + Serialize + DeserializeOwned + 'static,
{
    let Some(source) = source else {
        return Ok(Arc::new(MemoryTable::<T>::new()));
    };
    match &source.file {
        Some(file) if !file.path.trim().is_empty() => Ok(Arc::new(FileTable::<T>::new(
            &file.path,
            section,
            file.format,
        ))),
        Some(_) => Err(error::bad_value("source.file.path must name the file")),
        None => Err(error::bad_value("source must name a source kind: file")),
    }
}

/// Argon2id costs in a plugin config; a field left out is the library default.
#[derive(Debug, Clone, Default, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao)]
pub struct Argon2Config {
    /// Memory in KiB.
    pub memory_kib: Option<u32>,
    /// Passes over the memory.
    pub iterations: Option<u32>,
    /// Lanes.
    pub parallelism: Option<u32>,
}

impl Argon2Config {
    /// The costs, with the library default for each one left out.
    ///
    /// # Errors
    ///
    /// A bad-value error when Argon2 refuses the combination.
    pub fn params(&self) -> Result<Argon2Params, ProviderError> {
        let default = Argon2Params::default();
        Argon2Params::new(
            self.memory_kib.unwrap_or(default.memory_kib()),
            self.iterations.unwrap_or(default.iterations()),
            self.parallelism.unwrap_or(default.parallelism()),
        )
        .map_err(|reason| error::bad_value(&reason))
    }
}

/// Turns a table error met while building a provider into the error a host sees.
pub fn build_failed(what: &str, reason: &SourceError) -> ProviderError {
    error::bad_value(&format!("{what}: {reason}"))
}

/// A table of `T` kept in one private file: an array of tables named `section`, encoded in
/// the file's [`Format`].
///
/// A missing file is an empty table. Every read compares the file's [`Stamp`], so a write by
/// another process is a new revision; a file that is unreadable, oversized or invalid is an
/// error, never a stale answer. Errors never contain file contents.
pub struct FileTable<T> {
    path: PathBuf,
    section: &'static str,
    format: Format,
    state: Mutex<State>,
    _records: PhantomData<fn() -> T>,
}

struct State {
    stamp: Option<Stamp>,
    revision: u64,
}

impl<T> fmt::Debug for FileTable<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileTable")
            .field("path", &self.path)
            .field("section", &self.section)
            .finish_non_exhaustive()
    }
}

impl<T: Keyed + Clone + Serialize + DeserializeOwned> FileTable<T> {
    /// The table in the file at `path`, which need not exist yet.
    pub fn new(path: impl Into<PathBuf>, section: &'static str, format: Format) -> Self {
        Self {
            path: path.into(),
            section,
            format,
            state: Mutex::new(State {
                stamp: None,
                revision: 0,
            }),
            _records: PhantomData,
        }
    }

    fn decode(&self, text: &str) -> Result<Vec<T>, SourceError> {
        match self.format {
            Format::Toml => {
                let mut document: toml::Table = toml::from_str(text)
                    .map_err(|_| SourceError::invalid("file is invalid TOML"))?;
                let items = document.remove(self.section);
                if !document.is_empty() {
                    return Err(SourceError::invalid("file has an unknown top-level key"));
                }
                match items {
                    None => Ok(Vec::new()),
                    Some(toml::Value::Array(items)) => items
                        .into_iter()
                        .map(|item| {
                            item.try_into::<T>().map_err(|_| {
                                SourceError::invalid("a record in the file is invalid")
                            })
                        })
                        .collect(),
                    Some(_) => Err(SourceError::invalid("file section is not a list")),
                }
            }
        }
    }

    fn encode(&self, records: &[T]) -> Result<String, SourceError> {
        match self.format {
            Format::Toml => {
                let items = records
                    .iter()
                    .map(toml::Value::try_from)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| SourceError::invalid("records cannot be encoded"))?;
                let mut document = toml::Table::new();
                document.insert(self.section.to_owned(), toml::Value::Array(items));
                let text = toml::to_string(&document)
                    .map_err(|_| SourceError::invalid("records cannot be encoded"))?;
                if text.len() > MAX_TABLE_BYTES {
                    return Err(SourceError::invalid("table would exceed its size limit"));
                }
                Ok(text)
            }
        }
    }

    /// Reads the file and notes a new revision when it is not the one last seen.
    fn read(&self, state: &mut State) -> Result<Vec<T>, SourceError> {
        let unavailable = |reason: String| SourceError::unavailable(reason);
        let before = file::stamp(&self.path).map_err(unavailable)?;
        let records = match file::read_bounded(&self.path, MAX_TABLE_BYTES)
            .map_err(SourceError::unavailable)?
        {
            None => Vec::new(),
            Some(text) => self.decode(&text)?,
        };
        let after = file::stamp(&self.path).map_err(unavailable)?;
        if before != after {
            return Err(SourceError::unavailable("file changed while it was read"));
        }
        if after != state.stamp {
            state.stamp = after;
            state.revision += 1;
        }
        Ok(records)
    }

    fn write(&self, state: &mut State, records: &[T]) -> Result<(), SourceError> {
        let text = self.encode(records)?;
        file::write_private(&self.path, text.as_bytes()).map_err(SourceError::unavailable)?;
        state.stamp = file::stamp(&self.path).map_err(SourceError::unavailable)?;
        state.revision += 1;
        Ok(())
    }
}

impl<T: Keyed + Clone + Serialize + DeserializeOwned + Send> Table<T> for FileTable<T> {
    fn load(&self) -> Result<Snapshot<T>, SourceError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let records = self.read(&mut state)?;
        Ok(Snapshot::new(Revision::new(state.revision), records))
    }

    fn changes_since(&self, since: Revision) -> Result<Option<Snapshot<T>>, SourceError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let stamp = file::stamp(&self.path).map_err(SourceError::unavailable)?;
        if stamp == state.stamp && since.get() == state.revision {
            return Ok(None);
        }
        let records = self.read(&mut state)?;
        Ok(Some(Snapshot::new(Revision::new(state.revision), records)))
    }

    fn put(&self, record: T) -> Result<(), SourceError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let mut records = self.read(&mut state)?;
        match records.iter().position(|had| had.key() == record.key()) {
            Some(at) => records[at] = record,
            None => records.push(record),
        }
        self.write(&mut state, &records)
    }

    fn remove(&self, key: &str) -> Result<bool, SourceError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let mut records = self.read(&mut state)?;
        let before = records.len();
        records.retain(|record| record.key() != key);
        if records.len() == before {
            return Ok(false);
        }
        self.write(&mut state, &records)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Item {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    }

    impl Keyed for Item {
        fn key(&self) -> &str {
            &self.name
        }
    }

    fn item(name: &str) -> Item {
        Item {
            name: name.to_owned(),
            note: None,
        }
    }

    fn table(path: &std::path::Path) -> FileTable<Item> {
        FileTable::new(path, "items", Format::Toml)
    }

    #[test]
    fn a_missing_file_is_empty_and_a_put_creates_it() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("items.toml");
        let items = table(&path);
        assert!(items.load().unwrap().records.is_empty());
        items.put(item("a")).unwrap();
        items.put(item("b")).unwrap();
        items
            .put(Item {
                note: Some("n".into()),
                ..item("a")
            })
            .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("[[items]]"));
        let records = items.load().unwrap().records;
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].note.as_deref(), Some("n"));
        assert!(items.remove("b").unwrap());
        assert!(!items.remove("b").unwrap());
    }

    #[test]
    fn a_change_made_by_another_table_over_the_file_is_a_new_revision() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("items.toml");
        let one = table(&path);
        let other = table(&path);
        let first = one.load().unwrap();
        assert_eq!(one.changes_since(first.revision), Ok(None));
        other.put(item("a")).unwrap();
        let second = one.changes_since(first.revision).unwrap().unwrap();
        assert_eq!(second.records, [item("a")]);
        assert_eq!(one.changes_since(second.revision), Ok(None));
    }

    #[test]
    fn invalid_oversized_unknown_and_vanishing_files_are_errors() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("items.toml");
        let items = table(&path);
        for bad in [
            "surprise = 1",
            "items = [ { unknown = true } ]",
            "items = [",
        ] {
            std::fs::write(&path, bad).unwrap();
            let error = items.load().unwrap_err();
            assert!(!error.to_string().contains("unknown = true"));
        }
        std::fs::write(&path, vec![b' '; MAX_TABLE_BYTES + 1]).unwrap();
        assert!(items.load().is_err());
        std::fs::write(&path, "items = []").unwrap();
        assert!(items.load().unwrap().records.is_empty());
    }

    #[test]
    fn a_source_names_one_kind_or_none() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("items.toml");
        let named = SourceConfig::toml_file(path.to_str().unwrap());
        let opened = open_table::<Item>(Some(&named), "items").unwrap();
        opened.put(item("a")).unwrap();
        assert!(path.exists());
        // No source: in memory, nothing on disk.
        let memory = open_table::<Item>(None, "items").unwrap();
        memory.put(item("a")).unwrap();
        assert!(open_table::<Item>(Some(&SourceConfig::default()), "items").is_err());
        assert!(open_table::<Item>(Some(&SourceConfig::toml_file(" ")), "items").is_err());
        let beside = named.sibling("waiting");
        assert!(beside.file.unwrap().path.ends_with("items.toml.waiting"));
    }

    #[test]
    fn argon2_costs_default_and_are_checked() {
        assert_eq!(
            Argon2Config::default().params().unwrap(),
            Argon2Params::default()
        );
        let set = Argon2Config {
            memory_kib: Some(64),
            iterations: Some(1),
            ..Argon2Config::default()
        };
        assert_eq!(set.params().unwrap().memory_kib(), 64);
        let bad = Argon2Config {
            iterations: Some(0),
            ..Argon2Config::default()
        };
        assert!(bad.params().is_err());
    }
}
