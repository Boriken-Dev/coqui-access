//! What the product suites share: people, subjects and a store kept in a map.

#![allow(dead_code, reason = "each test binary uses part of it")]

use std::collections::BTreeMap;

use coqui_access::guatiao::Status;
use coqui_access::guatiao::library::ProviderError;
use coqui_access::{Person, Subject};
use coqui_access_acl::{AclStore, ItemAcl};

pub fn subject(text: &str) -> Subject {
    text.parse().unwrap()
}

pub fn person(name: &str, groups: &[&str]) -> Person {
    Person {
        id: format!("id-{name}"),
        name: name.to_owned(),
        groups: groups.iter().map(|group| (*group).to_owned()).collect(),
        ..Person::default()
    }
}

/// Items by path; `/a/b`'s parent is `/a`, and `/`'s is none.
#[derive(Default)]
pub struct PathStore {
    pub acls: BTreeMap<String, ItemAcl>,
    pub broken: bool,
}

impl PathStore {
    pub fn set(&mut self, path: &str, acl: ItemAcl) {
        self.acls.insert(path.to_owned(), acl);
    }
}

impl AclStore for PathStore {
    fn acl(&self, item: &str) -> Result<Option<ItemAcl>, ProviderError> {
        if self.broken {
            return Err(ProviderError::new(
                Status::GUATIAO_ERR_INTERNAL,
                "unreachable",
            ));
        }
        Ok(self.acls.get(item).cloned())
    }

    fn parent(&self, item: &str) -> Result<Option<String>, ProviderError> {
        Ok(match item.rsplit_once('/') {
            _ if item == "/" => None,
            Some(("", _)) => Some("/".to_owned()),
            Some((parent, _)) => Some(parent.to_owned()),
            None => None,
        })
    }
}
