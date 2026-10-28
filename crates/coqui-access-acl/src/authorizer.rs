//! The ACLs of a store, as coqui-access's `Authorizer` kind.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::ToString;
use core::fmt;

use coqui_access::guatiao::library::ProviderError;
use coqui_access::{AuthorizationDecision, AuthorizationRequest, Authorizer, Person, error};

use crate::check::{Context, Decision};
use crate::condition::Conditions;
use crate::error::AclError;
use crate::options::Options;
use crate::path::AclStore;
use crate::rights::{Rights, RightsSchema};

/// Answers [`Authorizer`] from the ACLs in a store: the request's `resource` is the item,
/// its `action` a right or alias of `schema`, its person the requester (signed in, so
/// `Authenticated` and `Everyone` entries match).
///
/// An action the schema does not define, or that names no right, is refused: nothing can
/// grant it. A store that cannot answer, or an ACL that cannot be used, is `Err` ("could
/// not find out"), never a denial. A superuser bypass is the caller's check before asking.
pub struct AclAuthorizer<S> {
    store: S,
    schema: RightsSchema,
    options: Options,
    owner_rights: Rights,
    conditions: Option<Box<dyn Conditions>>,
}

impl<S> fmt::Debug for AclAuthorizer<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AclAuthorizer")
            .field("rights", &self.schema.len())
            .field("options", &self.options)
            .field("owner_rights", &self.owner_rights)
            .field("conditions", &self.conditions.is_some())
            .finish_non_exhaustive()
    }
}

impl<S: AclStore> AclAuthorizer<S> {
    /// An authorizer over `store`, whose items' rights `schema` names, with default
    /// options, no owner rights and no conditions.
    pub fn new(store: S, schema: RightsSchema) -> Self {
        Self {
            store,
            schema,
            options: Options::default(),
            owner_rights: Rights::new(),
            conditions: None,
        }
    }

    /// The options checks run with.
    #[must_use]
    pub fn options(mut self, options: Options) -> Self {
        self.options = options;
        self
    }

    /// Rights an item's owner holds unless an entry names `Owner`
    /// ([`Context::owner_rights`]).
    #[must_use]
    pub fn owner_rights(mut self, rights: Rights) -> Self {
        self.owner_rights = rights;
        self
    }

    /// The consumer's conditions.
    #[must_use]
    pub fn conditions(mut self, conditions: impl Conditions + 'static) -> Self {
        self.conditions = Some(Box::new(conditions));
        self
    }

    /// The store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// The schema.
    pub fn schema(&self) -> &RightsSchema {
        &self.schema
    }

    /// The whole decision for `person` doing `action` on `item`, for an audit record or to
    /// intersect with a token's.
    ///
    /// # Errors
    ///
    /// As [`AclStore::check`]; an action the schema does not define is
    /// [`AclError::UnknownRight`].
    pub fn decide(&self, person: &Person, action: &str, item: &str) -> Result<Decision, AclError> {
        let wanted = self.schema.rights([action])?;
        let mut context = Context::new(&self.schema)
            .person(person)
            .owner_rights(self.owner_rights.clone())
            .options(self.options);
        if let Some(conditions) = &self.conditions {
            context = context.conditions(conditions.as_ref());
        }
        self.store.check(item, &context, &wanted)
    }
}

impl<S: AclStore + Send + Sync> Authorizer for AclAuthorizer<S> {
    fn authorize(
        &self,
        request: AuthorizationRequest,
    ) -> Result<AuthorizationDecision, ProviderError> {
        let refused = || AuthorizationDecision {
            allowed: false,
            limits: BTreeMap::new(),
        };
        match self.schema.rights([&request.action]) {
            Ok(wanted) if !wanted.is_empty() => {}
            _ => return Ok(refused()),
        }
        match self.decide(&request.person, &request.action, &request.resource) {
            Ok(decision) => Ok(AuthorizationDecision {
                allowed: decision.allowed,
                limits: BTreeMap::new(),
            }),
            Err(AclError::Store(error)) => Err(error),
            Err(other) => Err(error::internal(&other.to_string())),
        }
    }
}
