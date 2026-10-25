//! `coqui-roles` as a library a host loads: the Guatiao entry point and the config that
//! builds the authorizer.
//!
//! The config is structured data: the scope kinds, the roles and the ordered rules.
//!
//! ```json
//! { "scope_kinds": ["site"],
//!   "roles": [ { "name": "viewer", "actions": ["document.read"] } ],
//!   "rules": [ { "subject": "group:staff", "scope": "site:north", "role": "viewer" } ] }
//! ```
//!
//! Every key is optional; no rule means everything is denied.

use coqui_access::guatiao::library::ProviderError;
use coqui_access::guatiao::{FromValue, Provider, Schema, ToValue};
use coqui_access::{AuthorizationDecision, AuthorizationRequest, Authorizer, error};
use coqui_roles::{Role, RoleAuthorizer, RolePolicy, Rule};

/// One role in the config.
#[derive(Debug, Clone, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao)]
pub struct RoleConfig {
    /// The name rules refer to.
    pub name: String,
    /// The actions it allows.
    pub actions: Vec<String>,
}

/// One rule in the config.
#[derive(Debug, Clone, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao)]
pub struct RuleConfig {
    /// `account:<name>`, `person:<id>` or `group:<name>`.
    pub subject: String,
    /// `*` or `<kind>:<id>`.
    pub scope: String,
    /// The name of a role in `roles`.
    pub role: String,
}

/// Guatiao configuration for the role authorizer.
#[derive(Debug, Clone, Default, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao)]
pub struct RoleAuthorizerConfig {
    /// The scope kinds rules may use, such as `site`; empty allows any kind.
    #[map(default)]
    pub scope_kinds: Vec<String>,
    /// The roles.
    #[map(default)]
    pub roles: Vec<RoleConfig>,
    /// The rules, tried in order.
    #[map(default)]
    pub rules: Vec<RuleConfig>,
}

/// The role authorizer a host loads.
#[derive(Debug, Provider)]
#[provider(
    Authorizer,
    config = RoleAuthorizerConfig,
    id = "coqui_roles",
    name = "Role authorizer",
    crate = ::coqui_access::guatiao
)]
pub struct RoleAuthorizerProvider(RoleAuthorizer);

impl TryFrom<RoleAuthorizerConfig> for RoleAuthorizerProvider {
    type Error = ProviderError;

    fn try_from(config: RoleAuthorizerConfig) -> Result<Self, Self::Error> {
        let mut policy = RolePolicy::new();
        policy.scope_kinds = config.scope_kinds;
        policy.roles = config
            .roles
            .into_iter()
            .map(|role| Role::new(role.name, role.actions))
            .collect();
        policy.rules = config
            .rules
            .into_iter()
            .map(|rule| Rule::new(rule.subject, rule.scope, rule.role))
            .collect();
        RoleAuthorizer::new(policy)
            .map(Self)
            .map_err(|reason| error::bad_value(&reason.to_string()))
    }
}

impl Authorizer for RoleAuthorizerProvider {
    fn authorize(
        &self,
        request: AuthorizationRequest,
    ) -> Result<AuthorizationDecision, ProviderError> {
        self.0.authorize(request)
    }
}

coqui_access::guatiao::providers!(RoleAuthorizerProvider);

#[cfg(test)]
mod tests {
    use coqui_access::Person;

    use super::*;

    fn config(kinds: &[&str]) -> RoleAuthorizerConfig {
        RoleAuthorizerConfig {
            scope_kinds: kinds.iter().map(|kind| (*kind).to_owned()).collect(),
            roles: vec![RoleConfig {
                name: "editor".to_owned(),
                actions: vec!["document.write".to_owned()],
            }],
            rules: vec![RuleConfig {
                subject: "account:admin".to_owned(),
                scope: "site:north".to_owned(),
                role: "editor".to_owned(),
            }],
        }
    }

    fn may(provider: &RoleAuthorizerProvider, resource: &str) -> bool {
        provider
            .authorize(AuthorizationRequest {
                person: Person {
                    name: "admin".to_owned(),
                    ..Person::default()
                },
                action: "document.write".to_owned(),
                resource: resource.to_owned(),
            })
            .unwrap()
            .allowed
    }

    #[test]
    fn the_provider_builds_from_structured_configuration() {
        let provider = RoleAuthorizerProvider::try_from(config(&["site"])).unwrap();
        assert!(may(&provider, "site:north"));
        assert!(!may(&provider, "site:south"));
        assert!(RoleAuthorizerProvider::try_from(config(&["other"])).is_err());
        let nothing = RoleAuthorizerProvider::try_from(RoleAuthorizerConfig::default()).unwrap();
        assert!(!may(&nothing, "site:north"));
    }

    #[test]
    fn the_config_round_trips_through_a_guatiao_value() {
        let value = config(&["site"]).to_value().unwrap();
        let read = RoleAuthorizerConfig::from_value(&value).unwrap();
        assert_eq!(read.roles.len(), 1);
        assert_eq!(read.rules[0].subject, "account:admin");
        assert!(RoleAuthorizerProvider::try_from(read).is_ok());
    }
}
