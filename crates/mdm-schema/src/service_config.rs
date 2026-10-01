//! Registry of services managed by `com.apple.configuration.services.configuration-files`.
//!
//! The declaration's `ServiceType` is a free-text string, so a typo composes
//! cleanly and manages nothing: the device expands the archive into a
//! service-specific directory nobody reads, and the declaration still reports
//! Verified. This table is what turns that into an authoring-time error.
//!
//! Each entry records the path the archive must mirror, **relative to the
//! archive root**, because the archive reproduces the filesystem starting at
//! `/`. Staging `ssh/sshd_config` rather than `etc/ssh/sshd_config` is the
//! single most likely mistake and produces exactly the silent failure above.
//!
//! Source: `device-management/declarative/declarations/configurations/
//! services.configuration-files.yaml` (release branch). `cryptoTokenKit` and
//! `authorization` were added in the 26.1 schema.

use serde::Serialize;

/// Whether a service's managed configuration is a directory or a single file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ManagedKind {
    /// The whole directory is replaced (`/etc/ssh`, `/etc/pam.d`, …).
    Directory,
    /// A single file is replaced (`/etc/sudoers`, `/etc/profile`, …).
    File,
}

/// One service whose configuration files Apple lets an MDM manage.
#[derive(Debug, Clone, Serialize)]
pub struct ManagedService {
    /// `ServiceType` value, e.g. `com.apple.sshd`.
    pub service_type: &'static str,
    /// Paths the archive must contain, relative to its root, e.g. `etc/ssh`.
    /// More than one only for `com.apple.zsh`, which owns several files.
    pub archive_paths: &'static [&'static str],
    /// Directory or single file.
    pub kind: ManagedKind,
    /// What the operator would call it, for error messages.
    pub description: &'static str,
    /// Files whose absence almost certainly means a drop-in-only archive.
    ///
    /// Apple: "The service uses only the files the declaration provides and
    /// ignores the ones in its default directories." So an archive carrying
    /// only `etc/ssh/sshd_config.d/10-x.conf` removes `sshd_config` from the
    /// service's view rather than adding to it. A warning, not an error: a
    /// deliberately minimal directory is legal.
    pub expected_members: &'static [&'static str],
}

/// The services Apple documents as reading managed configuration files.
///
/// Not a gate on delivery. Any reverse-DNS `ServiceType` expands its archive
/// on device; this list is who *reads* the result. A third-party service does
/// so by calling `mcf_service_path_for_service_type` from
/// `libmanagedconfigurationfiles.dylib`.
pub const MANAGED_SERVICES: &[ManagedService] = &[
    ManagedService {
        service_type: "com.apple.sshd",
        archive_paths: &["etc/ssh"],
        kind: ManagedKind::Directory,
        description: "OpenSSH server configuration (/etc/ssh)",
        expected_members: &["etc/ssh/sshd_config"],
    },
    ManagedService {
        service_type: "com.apple.sudo",
        archive_paths: &["etc/sudoers"],
        kind: ManagedKind::File,
        description: "sudo policy (/etc/sudoers)",
        expected_members: &[],
    },
    ManagedService {
        service_type: "com.apple.pam",
        archive_paths: &["etc/pam.d"],
        kind: ManagedKind::Directory,
        description: "PAM service stack (/etc/pam.d)",
        expected_members: &[],
    },
    ManagedService {
        service_type: "com.apple.cups",
        archive_paths: &["etc/cups"],
        kind: ManagedKind::Directory,
        description: "CUPS printing (/etc/cups)",
        expected_members: &["etc/cups/cupsd.conf"],
    },
    ManagedService {
        service_type: "com.apple.apache.httpd",
        archive_paths: &["etc/apache2"],
        kind: ManagedKind::Directory,
        description: "Apache httpd (/etc/apache2)",
        expected_members: &["etc/apache2/httpd.conf"],
    },
    ManagedService {
        service_type: "com.apple.bash",
        archive_paths: &["etc/profile"],
        kind: ManagedKind::File,
        description: "bash system profile (/etc/profile)",
        expected_members: &[],
    },
    ManagedService {
        service_type: "com.apple.zsh",
        archive_paths: &[
            "etc/zprofile",
            "etc/zlogin",
            "etc/zlogout",
            "etc/zshenv",
            "etc/zshrc",
        ],
        kind: ManagedKind::File,
        description: "zsh system startup files (/etc/z*)",
        expected_members: &[],
    },
    ManagedService {
        service_type: "com.apple.cryptoTokenKit",
        archive_paths: &["etc/SmartcardLogin.plist"],
        kind: ManagedKind::File,
        description: "smartcard attribute mapping (/etc/SmartcardLogin.plist)",
        expected_members: &[],
    },
    ManagedService {
        service_type: "com.apple.authorization",
        archive_paths: &["Library/Security"],
        kind: ManagedKind::Directory,
        description: "SecurityAgent plugins and login banner (/Library/Security)",
        expected_members: &[],
    },
];

/// Look up a documented service.
pub fn find(service_type: &str) -> Option<&'static ManagedService> {
    MANAGED_SERVICES
        .iter()
        .find(|s| s.service_type == service_type)
}

/// Is this service type in Apple's reserved namespace?
///
/// Apple: "The system reserves the `com.apple` prefix for built-in services."
/// So a `com.apple.*` type absent from [`MANAGED_SERVICES`] is a typo, never a
/// service Apple added that this table has not learned about yet — and even if
/// it were, guessing its archive layout would be worse than refusing.
pub fn is_reserved_prefix(service_type: &str) -> bool {
    service_type == "com.apple" || service_type.starts_with("com.apple.")
}

/// Documented service types whose names are close to `input`, for a typo hint.
///
/// Prefix and containment only — a full edit distance is more machinery than a
/// nine-row table can repay.
pub fn suggestions(input: &str) -> Vec<&'static str> {
    let lower = input.to_lowercase();
    let tail = lower.rsplit('.').next().unwrap_or(&lower).to_string();
    MANAGED_SERVICES
        .iter()
        .filter(|s| {
            let known = s.service_type.to_lowercase();
            let known_tail = known.rsplit('.').next().unwrap_or(&known).to_string();
            known_tail.starts_with(&tail)
                || tail.starts_with(&known_tail)
                || known_tail.contains(&tail)
        })
        .map(|s| s.service_type)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_archive_path_is_relative_and_rooted_at_the_filesystem_root() {
        // A leading slash here would be copied into a layout check and reject
        // every correctly staged tree.
        for svc in MANAGED_SERVICES {
            for p in svc.archive_paths {
                assert!(
                    !p.starts_with('/'),
                    "{}: archive path {p} must be relative to the archive root",
                    svc.service_type
                );
                assert!(
                    !p.ends_with('/'),
                    "{}: archive path {p} must not carry a trailing slash",
                    svc.service_type
                );
            }
            assert!(
                !svc.archive_paths.is_empty(),
                "{}: needs at least one archive path",
                svc.service_type
            );
        }
    }

    #[test]
    fn expected_members_live_under_their_service_paths() {
        // A member outside the managed path could never appear in a valid
        // archive, so the warning would fire on every correct input.
        for svc in MANAGED_SERVICES {
            for m in svc.expected_members {
                assert!(
                    svc.archive_paths.iter().any(|p| m.starts_with(p)),
                    "{}: expected member {m} is outside {:?}",
                    svc.service_type,
                    svc.archive_paths
                );
            }
        }
    }

    #[test]
    fn the_apple_prefix_is_recognised_as_reserved() {
        assert!(is_reserved_prefix("com.apple.sshd"));
        assert!(is_reserved_prefix("com.apple.sshdd"));
        assert!(!is_reserved_prefix("com.example.demoapp"));
        // Not a prefix match on a lookalike domain.
        assert!(!is_reserved_prefix("com.appleseed.tool"));
    }

    #[test]
    fn a_typo_gets_a_suggestion() {
        assert!(suggestions("com.apple.sshdd").contains(&"com.apple.sshd"));
        assert!(suggestions("com.apple.ssh").contains(&"com.apple.sshd"));
    }

    #[test]
    fn lookup_finds_the_quietly_added_26_1_services() {
        // These two arrived without announcement and are the reason the
        // feature is worth wiring; a refactor dropping them would be silent.
        assert!(find("com.apple.cryptoTokenKit").is_some());
        assert!(find("com.apple.authorization").is_some());
        assert_eq!(
            find("com.apple.authorization").unwrap().archive_paths,
            &["Library/Security"]
        );
    }
}
