//! Two tables over one file, as two processes are: a read-modify-write is computed against
//! the records read under the file's lock, so no update is lost and a step is used once.

use std::borrow::Cow;
use std::sync::Arc;
use std::thread;

use coqui_access::guatiao::{FromValue, Schema, ToValue};
use coqui_access_kit::file::{Codec, CodecError, FileTable};
use coqui_access_kit::{Keyed, Reloading, SourceError, Table};
use serde::Serialize;
use serde::de::DeserializeSeed;

#[derive(Debug, Clone, PartialEq, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao, deny_unknown_fields)]
struct Counter {
    name: String,
    count: i64,
}

impl Keyed for Counter {
    fn key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.name)
    }
}

#[derive(Clone)]
struct Json;

impl Codec for Json {
    fn name(&self) -> &'static str {
        "JSON"
    }

    fn write<D: Serialize + ?Sized>(&self, document: &D) -> Result<String, CodecError> {
        serde_json::to_string_pretty(document).map_err(|_| CodecError::new())
    }

    fn read<'de, S: DeserializeSeed<'de>>(
        &self,
        text: &'de str,
        seed: S,
    ) -> Result<S::Value, CodecError> {
        let mut deserializer = serde_json::Deserializer::from_str(text);
        let read = seed
            .deserialize(&mut deserializer)
            .map_err(|_| CodecError::new())?;
        deserializer.end().map_err(|_| CodecError::new())?;
        Ok(read)
    }
}

fn reloading(path: &std::path::Path) -> Reloading<Counter> {
    let table: Arc<dyn Table<Counter>> = Arc::new(FileTable::new(path, "counters", Json));
    Reloading::new(table, |_| Ok(())).unwrap()
}

fn add_one(reloading: &Reloading<Counter>) {
    reloading
        .put_with(|records| {
            let count = records
                .iter()
                .find(|record| record.name == "n")
                .map_or(0, |record| record.count);
            Ok((
                Counter {
                    name: "n".to_owned(),
                    count: count + 1,
                },
                (),
            ))
        })
        .unwrap();
}

#[test]
fn no_update_is_lost_between_two_tables_over_one_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("counters.json");
    let (first, second) = (reloading(&path), reloading(&path));
    thread::scope(|scope| {
        scope.spawn(|| (0..40).for_each(|_| add_one(&first)));
        scope.spawn(|| (0..40).for_each(|_| add_one(&second)));
    });
    let seen = reloading(&path).read(|records| records[0].count).unwrap();
    assert_eq!(seen, 80);
}

#[test]
fn a_step_used_by_one_table_is_refused_to_the_other() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("counters.json");
    let (first, second) = (reloading(&path), reloading(&path));
    let take = |reloading: &Reloading<Counter>| {
        reloading.put_with(|records| {
            if records.iter().any(|record| record.name == "used") {
                return Err(SourceError::invalid("already used"));
            }
            Ok((
                Counter {
                    name: "used".to_owned(),
                    count: 1,
                },
                (),
            ))
        })
    };
    let outcomes = thread::scope(|scope| {
        let a = scope.spawn(|| take(&first).is_ok());
        let b = scope.spawn(|| take(&second).is_ok());
        [a.join().unwrap(), b.join().unwrap()]
    });
    assert_eq!(outcomes.iter().filter(|taken| **taken).count(), 1);
}

#[test]
fn the_size_bound_of_a_file_source_is_the_callers() {
    use coqui_access_kit::file::Source;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("big.json");
    let big = Counter {
        name: "x".repeat(1_300_000),
        count: 1,
    };
    let default = Source::file(path.to_str().unwrap(), Json)
        .open::<Counter>("counters")
        .unwrap();
    assert!(default.put(big.clone()).is_err(), "past the default 1 MiB");
    let raised = Source::file(path.to_str().unwrap(), Json)
        .max_bytes(2 * 1024 * 1024)
        .open::<Counter>("counters")
        .unwrap();
    raised.put(big).unwrap();
    // A provider's own default yields to what the configuration says.
    let kept = Source::file(path.to_str().unwrap(), Json)
        .max_bytes(10)
        .max_bytes_unless_set(4 * 1024 * 1024)
        .open::<Counter>("counters")
        .unwrap();
    assert!(kept.load().is_err(), "the configured 10 bytes held");
    let sibling = Source::file(path.to_str().unwrap(), Json)
        .max_bytes(77)
        .sibling("pending");
    assert_eq!(sibling.file.unwrap().max_bytes, Some(77));
}
