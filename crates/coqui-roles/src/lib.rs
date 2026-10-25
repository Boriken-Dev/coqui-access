//! A first-match role authorizer.
//!
//! A policy is TOML: named roles that list actions, and ordered `[[rule]]` entries that bind
//! one `account:<name>`, `person:<id>` or `group:<name>` to a role at one scope. A scope is
//! `*` (everything) or `<kind>:<id>`, where the kinds a deployment uses are configured, for
//! example `site` or `project`; the library has no scope vocabulary of its own. A request's
//! `resource` is compared with a rule's scope as an exact string.
//!
//! The first rule whose subject and scope match is decisive: when its role lacks the
//! requested action, access is denied. With no matching rule access is denied.
//!
//! ```toml
//! [role.viewer]
//! actions = ["document.read"]
//!
//! [[rule]]
//! subject = "group:staff"
//! scope = "site:north"
//! role = "viewer"
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;
use std::path::Path;

use coqui_access::guatiao::library::ProviderError;
use coqui_access::guatiao::{FromValue, Provider, Schema, ToValue};
use coqui_access::{AuthorizationDecision, AuthorizationRequest, Authorizer, Person, error};
use serde::Deserialize;

const MAX_POLICY_BYTES: usize = 1024 * 1024;
const MAX_ROLES: usize = 256;
const MAX_ROLE_ACTIONS: usize = 256;
const MAX_RULES: usize = 10_000;
const MAX_SCOPE_KINDS: usize = 64;

/// First-match role policy.
#[derive(Clone, Default)]
pub struct RoleAuthorizer {
    roles: BTreeMap<String, BTreeSet<String>>,
    rules: Vec<Rule>,
}

#[derive(Clone)]
struct Rule {
    subject: Subject,
    scope: String,
    role: String,
}

#[derive(Clone)]
enum Subject {
    Account(String),
    Person(String),
    Group(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    #[serde(default, rename = "role")]
    roles: BTreeMap<String, RoleDefinition>,
    #[serde(default, rename = "rule")]
    rules: Vec<RuleDefinition>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleDefinition {
    actions: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleDefinition {
    subject: String,
    scope: String,
    role: String,
}

/// An invalid or unreadable role policy.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RolePolicyError(String);

impl fmt::Display for RolePolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl core::error::Error for RolePolicyError {}

impl fmt::Debug for RoleAuthorizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RoleAuthorizer")
            .field("roles", &self.roles.len())
            .field("rules", &self.rules.len())
            .finish()
    }
}

impl RoleAuthorizer {
    /// Parses a policy from TOML.
    ///
    /// `scope_kinds` lists the kinds a rule scope may use (`site` allows `site:north`); an
    /// empty list allows any kind. `*` is always allowed.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown fields, unknown roles, malformed subjects or scopes,
    /// duplicate actions, or a policy past its size bounds.
    pub fn from_toml(source: &str, scope_kinds: &[String]) -> Result<Self, RolePolicyError> {
        let fail = |message: &str| RolePolicyError(message.to_owned());
        if source.len() > MAX_POLICY_BYTES {
            return Err(fail("policy exceeds the 1 MiB limit"));
        }
        if scope_kinds.len() > MAX_SCOPE_KINDS || !scope_kinds.iter().all(|kind| name(kind)) {
            return Err(fail("scope kinds are invalid"));
        }
        let document: Document = toml::from_str(source)
            .map_err(|error| RolePolicyError(format!("invalid policy: {error}")))?;
        if document.roles.len() > MAX_ROLES || document.rules.len() > MAX_RULES {
            return Err(fail("policy has too many roles or rules"));
        }
        let mut roles = BTreeMap::new();
        for (role, definition) in document.roles {
            if !name(&role) || definition.actions.is_empty() {
                return Err(RolePolicyError(format!("invalid role {role:?}")));
            }
            if definition.actions.len() > MAX_ROLE_ACTIONS {
                return Err(RolePolicyError(format!(
                    "role {role:?} has too many actions"
                )));
            }
            let mut actions = BTreeSet::new();
            for action in definition.actions {
                if !name(&action) || !actions.insert(action.clone()) {
                    return Err(RolePolicyError(format!(
                        "invalid or duplicate action {action:?} in role {role:?}"
                    )));
                }
            }
            roles.insert(role, actions);
        }

        let mut rules = Vec::with_capacity(document.rules.len());
        for rule in document.rules {
            let (kind, value) = rule
                .subject
                .split_once(':')
                .ok_or_else(|| fail("rule subject needs a kind and value"))?;
            if !name(value) {
                return Err(fail("rule subject value is invalid"));
            }
            let subject = match kind {
                "account" => Subject::Account(value.to_owned()),
                "person" => Subject::Person(value.to_owned()),
                "group" => Subject::Group(value.to_owned()),
                _ => return Err(fail("rule subject must be account, person or group")),
            };
            if rule.scope != "*" {
                let allowed = rule.scope.split_once(':').is_some_and(|(kind, id)| {
                    name(id)
                        && name(kind)
                        && (scope_kinds.is_empty() || scope_kinds.iter().any(|k| k == kind))
                });
                if !allowed {
                    return Err(RolePolicyError(format!(
                        "rule scope must be * or <kind>:<id> with kind in {scope_kinds:?}"
                    )));
                }
            }
            if !roles.contains_key(&rule.role) {
                return Err(RolePolicyError(format!(
                    "rule references unknown role {:?}",
                    rule.role
                )));
            }
            rules.push(Rule {
                subject,
                scope: rule.scope,
                role: rule.role,
            });
        }
        Ok(Self { roles, rules })
    }

    /// Reads and validates a policy file.
    ///
    /// # Errors
    ///
    /// As [`from_toml`](RoleAuthorizer::from_toml), and when the file cannot be read or is
    /// over 1 MiB.
    pub fn load(path: impl AsRef<Path>, scope_kinds: &[String]) -> Result<Self, RolePolicyError> {
        let path = path.as_ref();
        let mut source = String::new();
        std::fs::File::open(path)
            .and_then(|file| {
                file.take((MAX_POLICY_BYTES + 1) as u64)
                    .read_to_string(&mut source)
            })
            .map_err(|error| {
                RolePolicyError(format!(
                    "{}: could not read policy: {error}",
                    path.display()
                ))
            })?;
        Self::from_toml(&source, scope_kinds)
            .map_err(|error| RolePolicyError(format!("{}: {error}", path.display())))
    }

    fn decision(&self, request: &AuthorizationRequest) -> AuthorizationDecision {
        let allowed = self
            .rules
            .iter()
            .find(|rule| {
                (rule.scope == "*" || rule.scope == request.resource)
                    && subject_matches(&rule.subject, &request.person)
            })
            .is_some_and(|rule| {
                self.roles
                    .get(&rule.role)
                    .is_some_and(|actions| actions.contains(&request.action))
            });
        AuthorizationDecision {
            allowed,
            limits: BTreeMap::new(),
        }
    }
}

impl Authorizer for RoleAuthorizer {
    fn authorize(
        &self,
        request: AuthorizationRequest,
    ) -> Result<AuthorizationDecision, ProviderError> {
        Ok(self.decision(&request))
    }
}

/// Guatiao configuration for the role authorizer provider.
#[derive(Debug, Clone, FromValue, Schema, ToValue)]
#[map(crate = ::coqui_access::guatiao)]
#[non_exhaustive]
pub struct RoleAuthorizerConfig {
    /// Complete role and rule TOML source.
    pub policy_toml: String,
    /// The scope kinds rules may use, such as `site`; empty allows any kind.
    #[map(default = Vec::<String>::new())]
    pub scope_kinds: Vec<String>,
}

/// The role authorizer as a Guatiao provider.
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
        RoleAuthorizer::from_toml(&config.policy_toml, &config.scope_kinds)
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

fn subject_matches(subject: &Subject, person: &Person) -> bool {
    match subject {
        Subject::Account(name) => name == &person.name,
        Subject::Person(id) => id == &person.id,
        Subject::Group(group) => person.groups.iter().any(|member| member == group),
    }
}

fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn person(id: &str, name: &str, groups: &[&str]) -> Person {
        Person {
            id: id.to_owned(),
            name: name.to_owned(),
            groups: groups.iter().map(|group| (*group).to_owned()).collect(),
            ..Person::default()
        }
    }

    fn allowed(policy: &RoleAuthorizer, person: &Person, action: &str, resource: &str) -> bool {
        policy
            .authorize(AuthorizationRequest {
                person: person.clone(),
                action: action.to_owned(),
                resource: resource.to_owned(),
            })
            .unwrap()
            .allowed
    }

    const POLICY: &str = r#"
        [role.viewer]
        actions = ["document.read", "audit.read"]

        [role.editor]
        actions = ["document.read", "document.write"]

        [[rule]]
        subject = "group:staff"
        scope = "site:north"
        role = "viewer"

        [[rule]]
        subject = "person:p-editor"
        scope = "site:north"
        role = "editor"

        [[rule]]
        subject = "account:admin"
        scope = "*"
        role = "editor"
    "#;

    #[test]
    fn scopes_roles_and_default_deny() {
        let kinds = ["site".to_owned()];
        let policy = RoleAuthorizer::from_toml(POLICY, &kinds).unwrap();
        let debug = format!("{policy:?}");
        assert!(!debug.contains("p-editor") && !debug.contains("staff"));
        let viewer = person("p-viewer", "viewer", &["staff"]);
        let editor = person("p-editor", "editor", &[]);
        assert!(allowed(&policy, &viewer, "document.read", "site:north"));
        assert!(!allowed(&policy, &viewer, "document.write", "site:north"));
        assert!(!allowed(&policy, &viewer, "document.read", "site:south"));
        assert!(allowed(&policy, &editor, "document.write", "site:north"));
        assert!(!allowed(&policy, &editor, "document.write", "site:south"));
        assert!(allowed(
            &policy,
            &person("p", "admin", &[]),
            "document.write",
            "site:any"
        ));
        assert!(!allowed(
            &policy,
            &person("p", "nobody", &[]),
            "document.read",
            "site:north"
        ));
    }

    #[test]
    fn the_first_matching_rule_is_decisive() {
        let policy = RoleAuthorizer::from_toml(
            r#"
            [role.none]
            actions = ["x.nothing"]
            [role.all]
            actions = ["x.read"]
            [[rule]]
            subject = "group:g"
            scope = "*"
            role = "none"
            [[rule]]
            subject = "group:g"
            scope = "*"
            role = "all"
            "#,
            &[],
        )
        .unwrap();
        assert!(!allowed(
            &policy,
            &person("i", "n", &["g"]),
            "x.read",
            "anything"
        ));
    }

    #[test]
    fn scope_kinds_are_configurable_and_everything_else_is_refused() {
        // Another vocabulary works with no change to the library.
        let policy = RoleAuthorizer::from_toml(
            "[role.r]\nactions=['a.b']\n[[rule]]\nsubject='account:x'\nscope='project:p1'\nrole='r'",
            &["project".to_owned()],
        )
        .unwrap();
        assert!(allowed(
            &policy,
            &person("i", "x", &[]),
            "a.b",
            "project:p1"
        ));
        let rule = |scope: &str| {
            format!(
                "[role.r]\nactions=['a.b']\n[[rule]]\nsubject='account:x'\nscope='{scope}'\nrole='r'"
            )
        };
        let site = ["site".to_owned()];
        assert!(RoleAuthorizer::from_toml(&rule("project:p1"), &site).is_err());
        assert!(RoleAuthorizer::from_toml(&rule("site"), &site).is_err());
        assert!(RoleAuthorizer::from_toml(&rule("project:p1"), &[]).is_ok());
        assert!(
            RoleAuthorizer::from_toml(
                "[[rule]]\nsubject='account:x'\nscope='*'\nrole='missing'",
                &[]
            )
            .is_err()
        );
        assert!(RoleAuthorizer::from_toml(&" ".repeat(MAX_POLICY_BYTES + 1), &[]).is_err());
        assert!(RoleAuthorizer::from_toml("[role.r]\nactions=['a','a']", &[]).is_err());
        assert!(RoleAuthorizer::from_toml("surprise = 1", &[]).is_err());
    }

    #[test]
    fn the_provider_builds_from_its_configuration() {
        let provider = RoleAuthorizerProvider::try_from(RoleAuthorizerConfig {
            policy_toml: POLICY.to_owned(),
            scope_kinds: vec!["site".to_owned()],
        })
        .unwrap();
        assert!(allowed_by(&provider));
        assert!(
            RoleAuthorizerProvider::try_from(RoleAuthorizerConfig {
                policy_toml: POLICY.to_owned(),
                scope_kinds: vec!["other".to_owned()],
            })
            .is_err()
        );
    }

    fn allowed_by(provider: &RoleAuthorizerProvider) -> bool {
        provider
            .authorize(AuthorizationRequest {
                person: person("p", "admin", &[]),
                action: "document.write".to_owned(),
                resource: "site:north".to_owned(),
            })
            .unwrap()
            .allowed
    }
}
