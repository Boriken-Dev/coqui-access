//! A TOML table kept in one private file, read again whenever the file has been written.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::file::{self, Stamp};

/// The most a table file may hold, in bytes.
pub const MAX_TABLE_BYTES: usize = 1024 * 1024;

/// A document of type `T` kept in a TOML file.
///
/// A missing file is the default document. Every access compares the file's [`Stamp`] and
/// reads it again when another process wrote it; a file that has become unreadable,
/// oversized or invalid is an error, never a stale answer. Errors never contain file
/// contents.
pub struct Store<T> {
    path: PathBuf,
    validate: fn(&T) -> Result<(), String>,
    state: Mutex<State<T>>,
}

struct State<T> {
    value: T,
    stamp: Option<Stamp>,
}

impl<T> fmt::Debug for Store<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Store")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl<T: Serialize + DeserializeOwned + Default + Clone> Store<T> {
    /// Opens the table at `path`, which need not exist yet, checking it with `validate`.
    ///
    /// # Errors
    ///
    /// Returns an error when the file is unreadable, oversized, not valid TOML for `T`, or
    /// refused by `validate`.
    pub fn open(
        path: impl AsRef<Path>,
        validate: fn(&T) -> Result<(), String>,
    ) -> Result<Self, String> {
        let path = path.as_ref().to_path_buf();
        let (value, stamp) = load(&path, validate)?;
        Ok(Self {
            path,
            validate,
            state: Mutex::new(State { value, stamp }),
        })
    }

    /// The file this table is kept in.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Runs `read` over the current document.
    ///
    /// # Errors
    ///
    /// Returns an error when the file changed and can no longer be read.
    pub fn read<R>(&self, read: impl FnOnce(&T) -> R) -> Result<R, String> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        self.refresh(&mut state)?;
        Ok(read(&state.value))
    }

    /// Changes the current document and writes it, or leaves both untouched when `change`
    /// or validation refuses.
    ///
    /// # Errors
    ///
    /// Returns an error when the document cannot be read, `change` refuses, the result is
    /// invalid, or the file cannot be written.
    pub fn change<R>(&self, change: impl FnOnce(&mut T) -> Result<R, String>) -> Result<R, String> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        self.refresh(&mut state)?;
        let mut document = state.value.clone();
        let made = change(&mut document)?;
        (self.validate)(&document)?;
        let text = toml::to_string(&document).map_err(|_| "table cannot be encoded".to_owned())?;
        if text.len() > MAX_TABLE_BYTES {
            return Err("table would exceed its size limit".to_owned());
        }
        file::write_private(&self.path, text.as_bytes())?;
        state.stamp = file::stamp(&self.path)?;
        state.value = document;
        Ok(made)
    }

    fn refresh(&self, state: &mut State<T>) -> Result<(), String> {
        let stamp = file::stamp(&self.path)?;
        if stamp != state.stamp {
            let (value, stamp) = load(&self.path, self.validate)?;
            *state = State { value, stamp };
        }
        Ok(())
    }
}

fn load<T: DeserializeOwned + Default>(
    path: &Path,
    validate: fn(&T) -> Result<(), String>,
) -> Result<(T, Option<Stamp>), String> {
    let before = file::stamp(path)?;
    let value = match file::read_bounded(path, MAX_TABLE_BYTES)? {
        None => T::default(),
        Some(text) => {
            let value: T = toml::from_str(&text).map_err(|_| "file is invalid TOML".to_owned())?;
            validate(&value)?;
            value
        }
    };
    let after = file::stamp(path)?;
    if before != after {
        return Err("file changed while it was read".to_owned());
    }
    Ok((value, after))
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Table {
        #[serde(default)]
        names: Vec<String>,
    }

    fn few(table: &Table) -> Result<(), String> {
        if table.names.len() > 2 {
            Err("too many".to_owned())
        } else {
            Ok(())
        }
    }

    #[test]
    fn a_change_is_written_and_seen_by_another_open_store() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("table.toml");
        let one = Store::<Table>::open(&path, few).unwrap();
        let other = Store::<Table>::open(&path, few).unwrap();
        assert!(one.read(|t| t.names.is_empty()).unwrap());
        one.change(|t| {
            t.names.push("a".into());
            Ok(())
        })
        .unwrap();
        assert_eq!(other.read(|t| t.names.clone()).unwrap(), ["a"]);
    }

    #[test]
    fn a_refused_change_leaves_the_file_alone() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("table.toml");
        let store = Store::<Table>::open(&path, few).unwrap();
        for name in ["a", "b"] {
            store
                .change(|t| {
                    t.names.push(name.into());
                    Ok(())
                })
                .unwrap();
        }
        assert!(
            store
                .change(|t| {
                    t.names.push("c".into());
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(store.read(|t| t.names.len()).unwrap(), 2);
        assert!(store.change(|_| Err::<(), _>("no".to_owned())).is_err());
    }

    #[test]
    fn invalid_oversized_and_unknown_files_are_errors() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("table.toml");
        std::fs::write(&path, "surprise = 1").unwrap();
        assert!(Store::<Table>::open(&path, few).is_err());
        std::fs::write(&path, vec![b' '; MAX_TABLE_BYTES + 1]).unwrap();
        assert!(Store::<Table>::open(&path, few).is_err());
        std::fs::write(&path, "names = ['a','b','c']").unwrap();
        assert!(Store::<Table>::open(&path, few).is_err());
    }

    #[test]
    fn a_file_that_goes_bad_is_an_error_not_a_stale_answer() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("table.toml");
        let store = Store::<Table>::open(&path, few).unwrap();
        std::fs::write(&path, "names = [").unwrap();
        assert!(store.read(|_| ()).is_err());
    }
}
