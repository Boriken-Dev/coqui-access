//! Every bind method against a directory in a container: a Kerberos KDC and an OpenLDAP server
//! that refuses a simple bind on a connection with no confidentiality, as a hardened domain
//! controller does.
//!
//! The image is built from `tests/container/` by this test, the certificates are generated
//! here, and everything is removed afterwards. It runs only when `COQUI_TEST_CONTAINER` names
//! the runtime (`podman` or `docker`); without it the test passes without running and says so.
//! The `gssapi` scenarios also need the feature of that name and a Unix machine whose
//! libgssapi can reach the KDC the container publishes on loopback.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use coqui_access::guatiao::{FromValue, Map};
use coqui_access::{Attempt, Authenticator, Directory, Lookup, Verdict};
use coqui_access_ldap::{LdapAccounts, LdapAccountsConfig};
use guatiao_builder::Described;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    SanType,
};

const BASE: &str = "dc=example,dc=test";
const PERSON: &str = "uid=ana,ou=people,dc=example,dc=test";

/// What the test needs of the running directory.
struct Container {
    runtime: String,
    name: String,
    dir: tempfile::TempDir,
    ldap: u16,
    ldaps: u16,
    kdc: u16,
    ana_password: String,
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new(&self.runtime)
            .args(["rm", "-f", &self.name])
            .output();
        let _ = Command::new(&self.runtime)
            .args(["rmi", "-f", &self.image()])
            .output();
    }
}

fn run(runtime: &str, args: &[&str]) -> Output {
    Command::new(runtime)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("{runtime} {args:?}: {error}"))
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn random_text(prefix: &str) -> String {
    let mut bytes = [0_u8; 9];
    getrandom::fill(&mut bytes).unwrap();
    format!("{prefix}-{}", data_encoding::HEXLOWER.encode(&bytes))
}

impl Container {
    fn image(&self) -> String {
        format!("{}-image", self.name)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn start(runtime: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        for sub in ["in", "out", "sock", "client"] {
            fs::create_dir(dir.path().join(sub)).unwrap();
        }
        write_certificates(dir.path());
        let name = random_text("coqui-access-ldap-test");
        let admin_password = random_text("admin");
        let ana_password = random_text("ana");
        let context = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/container");
        let mut this = Self {
            runtime: runtime.to_owned(),
            name,
            dir,
            ldap: 0,
            ldaps: 0,
            kdc: 0,
            ana_password: ana_password.clone(),
        };
        let build = run(
            runtime,
            &[
                "build",
                "-q",
                "-t",
                &this.image(),
                "-f",
                context.join("Containerfile").to_str().unwrap(),
                context.to_str().unwrap(),
            ],
        );
        assert!(build.status.success(), "image build: {}", text(&build));
        let mount = |sub: &str, mode: &str| format!("{}:/{sub}:{mode}", this.path(sub).display());
        let started = run(
            runtime,
            &[
                "run",
                "-d",
                "--name",
                &this.name,
                "--hostname",
                "ldap.example.test",
                "-e",
                &format!("ADMIN_PW={admin_password}"),
                "-e",
                &format!("ANA_PW={ana_password}"),
                "-p",
                "127.0.0.1::389",
                "-p",
                "127.0.0.1::636",
                "-p",
                "127.0.0.1::88",
                "-v",
                &mount("in", "ro,z"),
                "-v",
                &mount("out", "z"),
                "-v",
                &mount("sock", "z"),
                &this.image(),
            ],
        );
        assert!(started.status.success(), "run: {}", text(&started));
        let deadline = Instant::now() + Duration::from_secs(120);
        while !this.path("out/ready").exists() {
            let logs = run(runtime, &["logs", &this.name]);
            assert!(Instant::now() < deadline, "not ready: {}", text(&logs));
            let state = run(
                runtime,
                &["inspect", "-f", "{{.State.Running}}", &this.name],
            );
            assert!(
                text(&state).trim() == "true",
                "the container stopped: {}",
                text(&logs)
            );
            std::thread::sleep(Duration::from_millis(250));
        }
        let port = |inner: &str| -> u16 {
            let output = run(runtime, &["port", &this.name, inner]);
            text(&output)
                .lines()
                .next()
                .and_then(|line| line.rsplit(':').next())
                .and_then(|port| port.trim().parse().ok())
                .unwrap_or_else(|| panic!("no published port for {inner}: {}", text(&output)))
        };
        let (ldap, ldaps, kdc) = (port("389/tcp"), port("636/tcp"), port("88/tcp"));
        (this.ldap, this.ldaps, this.kdc) = (ldap, ldaps, kdc);
        fs::write(
            this.path("client/krb5.conf"),
            format!(
                "[libdefaults]\n  default_realm = EXAMPLE.TEST\n  dns_lookup_kdc = false\n  \
                 dns_lookup_realm = false\n  rdns = false\n  dns_canonicalize_hostname = false\n  \
                 udp_preference_limit = 1\n[realms]\n  EXAMPLE.TEST = {{\n    kdc = 127.0.0.1:{kdc}\n  }}\n\
                 [domain_realm]\n  .example.test = EXAMPLE.TEST\n  example.test = EXAMPLE.TEST\n"
            ),
        )
        .unwrap();
        this
    }

    /// The provider's configuration for this directory; `more` adds or replaces keys.
    fn provider(&self, url: &str, more: impl FnOnce(&mut Map)) -> LdapAccounts {
        let mut value = Map::new();
        value.set("url", url.to_owned());
        value.set("base", BASE.to_owned());
        value.set("user_filter", "(uid={name})");
        value.set("name_attribute", "uid");
        value.set("group_attribute", "");
        value.set("group_filter", "(&(objectClass=groupOfNames)(member={dn}))");
        value.set("timeout_seconds", 10_u32);
        more(&mut value);
        let config = Described::<LdapAccountsConfig>::from_value(&value.into())
            .expect("the test configuration matches the provider schema")
            .0;
        LdapAccounts::new(config).expect("the test configuration is valid")
    }

    fn ca(&self) -> String {
        self.path("in/ca.pem").to_str().unwrap().to_owned()
    }
}

/// A CA, a server certificate for `localhost` and `ldap.example.test`, and a client certificate
/// whose common name is the account `extsvc`; each key as PEM.
fn write_certificates(dir: &Path) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Test CA");
    let ca_key = KeyPair::generate().unwrap();
    let ca_pem = ca_params.self_signed(&ca_key).unwrap().pem();
    let issuer = Issuer::new(ca_params, ca_key);

    let mut server = CertificateParams::new(Vec::<String>::new()).unwrap();
    server
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    server.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into().unwrap()),
        SanType::DnsName("ldap.example.test".try_into().unwrap()),
        SanType::IpAddress("127.0.0.1".parse().unwrap()),
    ];
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate().unwrap();
    let server_pem = server.signed_by(&server_key, &issuer).unwrap().pem();

    let mut client = CertificateParams::new(Vec::<String>::new()).unwrap();
    client
        .distinguished_name
        .push(DnType::OrganizationName, "coqui test");
    client.distinguished_name.push(DnType::CommonName, "extsvc");
    client.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = KeyPair::generate().unwrap();
    let client_pem = client.signed_by(&client_key, &issuer).unwrap().pem();

    for (name, content) in [
        ("in/ca.pem", ca_pem),
        ("in/server.pem", server_pem),
        ("in/server.key", server_key.serialize_pem()),
        ("client/client.pem", client_pem),
        ("client/client.key", client_key.serialize_pem()),
    ] {
        fs::write(dir.join(name), content).unwrap();
    }
}

fn attempt(name: &str, secret: &str) -> Attempt {
    Attempt {
        name: Some(name.to_owned()),
        secret: Some(secret.to_owned()),
        headers: Vec::new(),
        peer: None,
        secure: Some(false),
        certificate: None,
        certificates: None,
        method: None,
        challenge: None,
    }
}

fn lookup_ana(accounts: &LdapAccounts) -> Option<coqui_access::Person> {
    accounts
        .lookup(Lookup {
            by: "name".to_owned(),
            value: "ana".to_owned(),
            ..Lookup::default()
        })
        .expect("the directory answers the lookup")
}

fn assert_ana(accounts: &LdapAccounts) {
    let person = lookup_ana(accounts).expect("ana resolves");
    assert_eq!(person.id, PERSON);
    assert_eq!(person.groups, ["operators"]);
}

#[test]
fn every_bind_method_binds_against_a_directory_that_wants_confidentiality() {
    let Ok(runtime) = std::env::var("COQUI_TEST_CONTAINER") else {
        eprintln!(
            "skipped: set COQUI_TEST_CONTAINER=podman (or docker) to run the container directory tests"
        );
        return;
    };
    let directory = Container::start(&runtime);
    let ca = directory.ca();
    let ldaps = format!("ldaps://localhost:{}", directory.ldaps);
    let plain = format!("ldap://127.0.0.1:{}", directory.ldap);

    // Simple over TLS: the person's password, right and wrong, and a lookup.
    let simple = directory.provider(&ldaps, |value| {
        value.set("ca_file", ca.clone());
        value.set("bind", "uid=ana,ou=people,dc=example,dc=test");
        value.set("bind_password", directory.ana_password.clone());
    });
    assert_ana(&simple);
    let Verdict::Valid(valid) = simple
        .authenticate(attempt("ana", &directory.ana_password))
        .unwrap()
    else {
        panic!("ana's password is accepted");
    };
    assert_eq!(valid.value, "ana");
    assert_eq!(
        simple.authenticate(attempt("ana", "wrong")).unwrap(),
        Verdict::Invalid
    );

    // Control: the directory refuses a simple bind with no confidentiality, as a domain
    // controller that requires signing does, so the methods below are what gets through.
    let refused = directory.provider(&plain, |value| {
        value.set("bind", "uid=ana,ou=people,dc=example,dc=test");
        value.set("bind_password", directory.ana_password.clone());
    });
    assert!(
        refused
            .lookup(Lookup {
                by: "name".to_owned(),
                value: "ana".to_owned(),
                ..Lookup::default()
            })
            .is_err()
    );

    // External with the client certificate: over ldaps and over StartTLS.
    let certificate = |value: &mut Map| {
        value.set("ca_file", directory.ca());
        value.set("bind_method", "external");
        value.set(
            "client_cert",
            directory
                .path("client/client.pem")
                .to_str()
                .unwrap()
                .to_owned(),
        );
        value.set(
            "client_key",
            directory
                .path("client/client.key")
                .to_str()
                .unwrap()
                .to_owned(),
        );
    };
    let external = directory.provider(&ldaps, certificate);
    assert_ana(&external);
    let starttls = directory.provider(&format!("ldap://localhost:{}", directory.ldap), |value| {
        certificate(value);
        value.set("start_tls", true);
    });
    assert_ana(&starttls);

    // External over the unix socket, as the process behind it.
    #[cfg(unix)]
    {
        let socket = directory.path("sock/ldapi");
        let url = format!("ldapi://{}", socket.to_str().unwrap().replace('/', "%2F"));
        let local = directory.provider(&url, |value| value.set("bind_method", "external"));
        assert_ana(&local);
    }

    // Control: no client certificate, no identity.
    let anonymous = directory.provider(&ldaps, |value| {
        value.set("ca_file", directory.ca());
        value.set("bind_method", "simple");
    });
    assert!(
        anonymous
            .lookup(Lookup {
                by: "name".to_owned(),
                value: "ana".to_owned(),
                ..Lookup::default()
            })
            .map(|person| person.is_none())
            .unwrap_or(true)
    );

    #[cfg(all(unix, feature = "gssapi"))]
    gssapi(&directory, &plain, &ldaps);
}

/// GSSAPI as the keytab of `svc@EXAMPLE.TEST` the container exported. The credentials are the
/// process's, so they are set in its environment, once, before any provider is built.
#[cfg(all(unix, feature = "gssapi"))]
fn gssapi(directory: &Container, plain: &str, ldaps: &str) {
    // SAFETY: this is the only test in the binary, and it has started no thread of its own.
    unsafe {
        std::env::set_var("KRB5_CONFIG", directory.path("client/krb5.conf"));
        std::env::set_var("KRB5_CLIENT_KTNAME", directory.path("out/svc.keytab"));
        std::env::set_var(
            "KRB5CCNAME",
            format!("FILE:{}", directory.path("client/cc").display()),
        );
    }
    let sealed = directory.provider(plain, |value| {
        value.set("bind_method", "gssapi");
        value.set("server_fqdn", "ldap.example.test");
    });
    // A search over a sealed layer; the password of a person is checked on the same sealed
    // connection, where the server's simple-bind rule is met.
    assert_ana(&sealed);
    assert!(matches!(
        sealed
            .authenticate(attempt("ana", &directory.ana_password))
            .unwrap(),
        Verdict::Valid(_)
    ));
    assert_eq!(
        sealed.authenticate(attempt("ana", "wrong")).unwrap(),
        Verdict::Invalid
    );

    // Over TLS the certificate's hash goes along as the channel binding.
    let secured = directory.provider(ldaps, |value| {
        value.set("ca_file", directory.ca());
        value.set("bind_method", "gssapi");
        value.set("server_fqdn", "ldap.example.test");
    });
    assert_ana(&secured);

    // Control: the wrong service name is a Kerberos failure, not a bind as somebody else.
    let wrong = directory.provider(plain, |value| {
        value.set("bind_method", "gssapi");
        value.set("server_fqdn", "wrong.example.test");
    });
    assert!(
        wrong
            .lookup(Lookup {
                by: "name".to_owned(),
                value: "ana".to_owned(),
                ..Lookup::default()
            })
            .is_err()
    );
}
