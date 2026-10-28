//! Rights as a growable bit set, and the per-item-type schema that names them.

use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Sub, SubAssign};

use crate::error::AclError;
use crate::options::Limits;

/// A set of rights, one bit per right a [`RightsSchema`] defines. It grows as wide as the
/// schema needs: Windows uses 32 bits, NFSv4 14, Proxmox about 60.
///
/// Bits mean nothing without their schema; store names ([`Entry::rights`]) and compile them
/// with [`RightsSchema::rights`].
///
/// [`Entry::rights`]: crate::Entry::rights
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct Rights {
    /// Never ends in a zero word, so equal sets compare equal.
    words: Vec<u64>,
}

impl Rights {
    /// The empty set.
    pub const fn new() -> Self {
        Self { words: Vec::new() }
    }

    /// Whether `bit` is in the set.
    pub fn contains(&self, bit: usize) -> bool {
        self.words
            .get(bit / 64)
            .is_some_and(|word| word & (1 << (bit % 64)) != 0)
    }

    /// Adds `bit`; `true` when it was not there.
    pub fn insert(&mut self, bit: usize) -> bool {
        let at = bit / 64;
        if self.words.len() <= at {
            self.words.resize(at + 1, 0);
        }
        let had = self.words[at] & (1 << (bit % 64)) != 0;
        self.words[at] |= 1 << (bit % 64);
        !had
    }

    /// Removes `bit`; `true` when it was there.
    pub fn remove(&mut self, bit: usize) -> bool {
        let had = self.contains(bit);
        if had {
            self.words[bit / 64] &= !(1 << (bit % 64));
            self.trim();
        }
        had
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }

    /// How many rights the set holds.
    pub fn len(&self) -> usize {
        self.words
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }

    /// Whether every right here is also in `other`.
    pub fn is_subset(&self, other: &Rights) -> bool {
        self.words
            .iter()
            .enumerate()
            .all(|(at, word)| word & !other.words.get(at).copied().unwrap_or(0) == 0)
    }

    /// Whether the two sets share no right.
    pub fn is_disjoint(&self, other: &Rights) -> bool {
        self.words
            .iter()
            .zip(&other.words)
            .all(|(one, two)| one & two == 0)
    }

    /// The bits in the set, lowest first.
    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.words.iter().enumerate().flat_map(|(at, word)| {
            (0..64)
                .filter(move |bit| word & (1 << bit) != 0)
                .map(move |bit| at * 64 + bit)
        })
    }

    fn trim(&mut self) {
        while self.words.last() == Some(&0) {
            self.words.pop();
        }
    }

    fn zip_with(&self, other: &Rights, combine: impl Fn(u64, u64) -> u64) -> Rights {
        let width = self.words.len().max(other.words.len());
        let word = |words: &[u64], at: usize| words.get(at).copied().unwrap_or(0);
        let mut combined = Rights {
            words: (0..width)
                .map(|at| combine(word(&self.words, at), word(&other.words, at)))
                .collect(),
        };
        combined.trim();
        combined
    }
}

impl fmt::Debug for Rights {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_set().entries(self.iter()).finish()
    }
}

impl FromIterator<usize> for Rights {
    fn from_iter<I: IntoIterator<Item = usize>>(bits: I) -> Self {
        let mut rights = Rights::new();
        rights.extend(bits);
        rights
    }
}

impl Extend<usize> for Rights {
    fn extend<I: IntoIterator<Item = usize>>(&mut self, bits: I) {
        for bit in bits {
            self.insert(bit);
        }
    }
}

impl BitOr for &Rights {
    type Output = Rights;

    fn bitor(self, other: &Rights) -> Rights {
        self.zip_with(other, |one, two| one | two)
    }
}

impl BitAnd for &Rights {
    type Output = Rights;

    fn bitand(self, other: &Rights) -> Rights {
        self.zip_with(other, |one, two| one & two)
    }
}

impl Sub for &Rights {
    type Output = Rights;

    fn sub(self, other: &Rights) -> Rights {
        self.zip_with(other, |one, two| one & !two)
    }
}

impl BitOrAssign<&Rights> for Rights {
    fn bitor_assign(&mut self, other: &Rights) {
        *self = &*self | other;
    }
}

impl BitAndAssign<&Rights> for Rights {
    fn bitand_assign(&mut self, other: &Rights) {
        *self = &*self & other;
    }
}

impl SubAssign<&Rights> for Rights {
    fn sub_assign(&mut self, other: &Rights) {
        *self = &*self - other;
    }
}

/// What a name stands for.
#[derive(Debug, Clone)]
struct Named {
    rights: Rights,
    cancels: bool,
}

/// The rights one type of item has, by name, and the aliases that stand for several.
///
/// A right is one bit, numbered in the order it is defined. An alias names a set of rights
/// and earlier aliases: Windows generic rights, NFSv4 basic permissions and Proxmox roles
/// are all aliases. A cancelling name ([`RightsSchemaBuilder::cancel`]) grants nothing, and
/// an entry naming it denies everything (Proxmox's `NoAccess`).
///
/// ```
/// use coqui_access_acl::RightsSchema;
///
/// let schema = RightsSchema::builder()
///     .right("read_data")
///     .right("read_attributes")
///     .right("write_data")
///     .alias("read", ["read_data", "read_attributes"])
///     .build()?;
/// assert_eq!(schema.rights(["read"])?, schema.rights(["read_data", "read_attributes"])?);
/// assert!(schema.rights(["delete"]).is_err());
/// # Ok::<(), coqui_access_acl::AclError>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct RightsSchema {
    bits: Vec<String>,
    names: BTreeMap<String, Named>,
}

impl RightsSchema {
    /// Starts a schema; rights take bits in the order they are added.
    pub fn builder() -> RightsSchemaBuilder {
        RightsSchemaBuilder::default()
    }

    /// How many rights (bits) the schema defines; aliases are not counted.
    pub fn len(&self) -> usize {
        self.bits.len()
    }

    /// Whether the schema defines no right.
    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }

    /// The bit of the right `name`; `None` for an alias or an unknown name.
    pub fn bit(&self, name: &str) -> Option<usize> {
        self.bits.iter().position(|bit| bit == name)
    }

    /// Every right the schema defines.
    pub fn all(&self) -> Rights {
        (0..self.bits.len()).collect()
    }

    /// Whether `name` cancels everything.
    pub fn cancels(&self, name: &str) -> bool {
        self.names.get(name).is_some_and(|named| named.cancels)
    }

    /// The rights `names` stand for together: rights and aliases, unioned.
    ///
    /// # Errors
    ///
    /// [`AclError::UnknownRight`] with the position of the first name the schema lacks.
    pub fn rights<I, S>(&self, names: I) -> Result<Rights, AclError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut rights = Rights::new();
        for (at, name) in names.into_iter().enumerate() {
            let named = self
                .names
                .get(name.as_ref())
                .ok_or(AclError::UnknownRight { entry: None, at })?;
            rights |= &named.rights;
        }
        Ok(rights)
    }

    /// The names of the rights in `rights`, lowest bit first; a bit the schema does not
    /// define is left out.
    pub fn names<'a>(&'a self, rights: &Rights) -> Vec<&'a str> {
        rights
            .iter()
            .filter_map(|bit| self.bits.get(bit).map(String::as_str))
            .collect()
    }

    /// The rights and whether any name cancels, or the position of the first unknown name.
    pub(crate) fn compile(&self, names: &[String]) -> Result<(Rights, bool), usize> {
        let mut rights = Rights::new();
        let mut cancels = false;
        for (at, name) in names.iter().enumerate() {
            let named = self.names.get(name).ok_or(at)?;
            rights |= &named.rights;
            cancels |= named.cancels;
        }
        Ok((rights, cancels))
    }
}

/// Builds a [`RightsSchema`].
#[derive(Debug, Clone, Default)]
#[must_use]
pub struct RightsSchemaBuilder {
    rights: Vec<String>,
    aliases: Vec<(String, Vec<String>, bool)>,
    limits: Limits,
}

impl RightsSchemaBuilder {
    /// Defines a right, with the next bit.
    pub fn right(mut self, name: impl Into<String>) -> Self {
        self.rights.push(name.into());
        self
    }

    /// Defines several rights, in order.
    pub fn rights(mut self, names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.rights.extend(names.into_iter().map(Into::into));
        self
    }

    /// Defines an alias for rights and aliases defined before it.
    pub fn alias(
        mut self,
        name: impl Into<String>,
        members: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.aliases.push((
            name.into(),
            members.into_iter().map(Into::into).collect(),
            false,
        ));
        self
    }

    /// Defines a name that grants nothing and cancels every grant where it is in force.
    pub fn cancel(mut self, name: impl Into<String>) -> Self {
        self.aliases.push((name.into(), Vec::new(), true));
        self
    }

    /// The bounds the schema is built within; only [`Limits::rights`] applies here.
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Checks the names and builds the schema.
    ///
    /// # Errors
    ///
    /// [`AclError::InvalidName`] for an empty name or one holding a control character,
    /// [`AclError::DuplicateName`], [`AclError::UnknownRight`] for an alias member not defined
    /// before it, [`AclError::TooManyRights`] past [`Limits::rights`].
    pub fn build(self) -> Result<RightsSchema, AclError> {
        if self
            .limits
            .rights
            .is_some_and(|max| self.rights.len() > max)
        {
            return Err(AclError::TooManyRights);
        }
        let mut schema = RightsSchema::default();
        let add = |schema: &mut RightsSchema, name: &str, named: Named| {
            if name.is_empty() || name.chars().any(char::is_control) {
                return Err(AclError::InvalidName);
            }
            if schema.names.insert(name.to_owned(), named).is_some() {
                return Err(AclError::DuplicateName);
            }
            Ok(())
        };
        for (bit, name) in self.rights.iter().enumerate() {
            let rights = core::iter::once(bit).collect();
            add(
                &mut schema,
                name,
                Named {
                    rights,
                    cancels: false,
                },
            )?;
            schema.bits.push(name.clone());
        }
        for (name, members, cancels) in &self.aliases {
            let (rights, cancelling) = schema
                .compile(members)
                .map_err(|at| AclError::UnknownRight { entry: None, at })?;
            let named = Named {
                rights,
                cancels: *cancels || cancelling,
            };
            add(&mut schema, name, named)?;
        }
        Ok(schema)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_set_grows_past_one_word_and_compares_by_content() {
        let mut wide: Rights = [1, 70, 130].into_iter().collect();
        assert!(wide.contains(70) && !wide.contains(71));
        assert_eq!(wide.len(), 3);
        assert!(wide.remove(130));
        assert!(!wide.remove(130));
        assert_eq!(wide, [70, 1].into_iter().collect());
        let narrow: Rights = [1].into_iter().collect();
        assert!(narrow.is_subset(&wide) && !wide.is_subset(&narrow));
        assert_eq!(&wide - &narrow, [70].into_iter().collect());
        assert_eq!(&wide & &narrow, narrow);
        assert!((&wide - &wide).is_empty());
        assert_eq!(wide.iter().collect::<Vec<_>>(), [1, 70]);
        assert!(narrow.is_disjoint(&[70].into_iter().collect()));
    }

    #[test]
    fn names_compile_to_bits_and_unknown_or_repeated_names_are_refused() {
        let schema = RightsSchema::builder()
            .rights(["a", "b", "c"])
            .alias("ab", ["a", "b"])
            .alias("abc", ["ab", "c"])
            .cancel("none")
            .build()
            .unwrap();
        assert_eq!(schema.len(), 3);
        assert_eq!(schema.rights(["abc"]).unwrap(), schema.all());
        assert_eq!(schema.names(&schema.rights(["ab"]).unwrap()), ["a", "b"]);
        assert!(schema.cancels("none") && !schema.cancels("a"));
        assert!(schema.rights(["none"]).unwrap().is_empty());
        assert!(matches!(
            schema.rights(["a", "zz"]),
            Err(AclError::UnknownRight { at: 1, .. })
        ));
        for bad in [
            RightsSchema::builder().rights(["a", "a"]),
            RightsSchema::builder().right("a").alias("a", ["a"]),
            RightsSchema::builder().right(""),
            RightsSchema::builder().alias("x", ["missing"]),
            RightsSchema::builder()
                .rights(["a", "b"])
                .limits(Limits::default().rights(Some(1))),
        ] {
            assert!(bad.build().is_err());
        }
        let many = (0..2000).map(|bit| alloc::format!("r{bit}"));
        assert!(
            RightsSchema::builder()
                .rights(many.clone())
                .build()
                .is_err()
        );
        let unbounded = Limits::default().rights(None);
        let wide = RightsSchema::builder()
            .rights(many)
            .limits(unbounded)
            .build()
            .unwrap();
        assert_eq!(wide.all().len(), 2000);
    }
}
