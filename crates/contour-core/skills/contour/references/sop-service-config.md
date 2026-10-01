# SOP: Service Configuration Files (DDM)

`com.apple.configuration.services.configuration-files` replaces a service's
on-disk configuration with a zip the device expands into a SIP-protected
location. The declaration is two keys; the work is the archive, and two
distinct things change independently — its CONTENT and its LOCATION. Conflating
them is how a fleet either re-downloads identical bytes or verifies against
content nobody reviewed.

`contour profile ddm service-config` owns both.

Format spec: `crates/contour-core/skills/contour/references/sop-format-spec.md`
Drift detector: `crates/profile/tests/sop_traps.rs`

---

## WHEN TO USE

Route here when the user wants to manage a **text configuration file that
lives on disk**, not a preference domain:

- `sshd_config`, `sudoers`, `pam.d`, `cups`, `apache2`, shell profiles
- `/etc/SmartcardLogin.plist` — smartcard attribute mapping
- `/Library/Security` — SecurityAgentPlugins (XCreds), login banner
- a third-party app's config file, delivered read-only and SIP-protected

Do NOT route here for anything expressible as a managed preference or an
existing configuration declaration. A profile payload or a typed DDM
configuration is always the better answer when one exists.

## WHAT THE DEVICE DOES

The device downloads the asset's zip, expands it under
`/var/db/ManagedConfigurationFiles` (SIP-protected), and the service reads from
there instead of its default directory. Expanded files are mode `444`,
read-only for everyone. Links in the archive cannot escape the service
directory.

Requirements: macOS 14+, **supervised**, system scope. `apply: multiple`, so
several services can be managed at once with one declaration each.

## SERVICE_REGISTRY

| ServiceType | Archive must mirror | Kind |
|---|---|---|
| `com.apple.sshd` | `etc/ssh/` | directory |
| `com.apple.sudo` | `etc/sudoers` | file |
| `com.apple.pam` | `etc/pam.d/` | directory |
| `com.apple.cups` | `etc/cups/` | directory |
| `com.apple.apache.httpd` | `etc/apache2/` | directory |
| `com.apple.bash` | `etc/profile` | file |
| `com.apple.zsh` | `etc/zprofile`, `etc/zlogin`, `etc/zlogout`, `etc/zshenv`, `etc/zshrc` | files |
| `com.apple.cryptoTokenKit` | `etc/SmartcardLogin.plist` | file |
| `com.apple.authorization` | `Library/Security/` | directory |

Paths are **relative to the archive root** and mirror the filesystem from `/`.
The `com.apple` prefix is reserved: a `com.apple.*` type not in this table is a
typo, not a new service.

Any other reverse-DNS `ServiceType` delivers files successfully — this is
verified behaviour, not speculation — but nothing reads them unless the service
calls `mcf_service_path_for_service_type` from
`libmanagedconfigurationfiles.dylib`, or something local points at the managed
path. See THIRD_PARTY_SERVICES.

## ERROR-CODE ENUM

Agents MUST switch on `error_code`, never on the prose `error` field.

```
ARCHIVE_LAYOUT         archive is not rooted at the filesystem root
UNKNOWN_SERVICE_TYPE   com.apple.* type Apple does not document, or not reverse-DNS
CONTENT_MOVED          re-host found a changed hash — that is a republish, not a move
SCHEMA_VIOLATION       failed Apple-schema validation
INVALID_ORG            org domain malformed or absent
IO_ERROR               file not found, permission denied, disk full
UNKNOWN                unmatched — treat as fatal, do NOT auto-retry
```

---

## PROCEDURE deploy_service_config(service_type, source_dir, org, url)

```
SCHEMA_SOURCE: apple/device-management (release branch)
SCHEMA_TOOL:   contour profile ddm info com.apple.configuration.services.configuration-files --json

INPUT:
  service_type : e.g. com.apple.sshd — see SERVICE_REGISTRY
  source_dir   : staging directory whose layout mirrors / (the filesystem root)
  org          : reverse-domain identifier; contour refuses com.example
  url          : https URL the archive will be hosted at, pinned to an
                 immutable path (a commit SHA or content hash — NOT a
                 branch or a mutable "latest")

PRECONDITIONS:
  ASSERT service_type matches /^[a-z0-9-]+(\.[a-z0-9-]+)+$/
    HALT "ServiceType must be reverse-DNS; got '{service_type}'"

  if service_type starts with "com.apple.":
    ASSERT service_type in SERVICE_REGISTRY
      HALT "'{service_type}' is not an Apple-managed service; the com.apple
            prefix is reserved. Closest: {suggestions}"

  ASSERT target is supervised AND macOS >= 14
    HALT "service configuration files require a supervised Mac on macOS 14+"

  ASSERT org != "com.example"
    HALT "refusing default 'com.example'"

STEP 1 — Verify the archive layout BEFORE packing:
  # This is the trap that produces a Verified declaration managing nothing.
  expected = SERVICE_REGISTRY[service_type].path      # e.g. etc/ssh/
  ASSERT source_dir contains expected
    HALT "archive root must contain '{expected}'; found {top_level_entries}.
          Stage the tree as it appears from /, e.g. {source_dir}/etc/ssh/sshd_config"

STEP 2 — Check for the partial-archive mistake:
  # Apple: "The service uses only the files the declaration provides and
  # ignores the ones in its default directories." A drop-in-only archive
  # therefore REMOVES the service's main configuration.
  if service_type == "com.apple.sshd" AND "etc/ssh/sshd_config" not in files:
    WARN "archive has no etc/ssh/sshd_config — sshd will see ONLY the files
          in this archive and none of /etc/ssh. If a drop-in was intended,
          include the full directory. Continuing."
  # Same shape for the other directory services: sudoers, pam.d, cups, apache2.

STEP 3 — Build: pack, hash, and compose in one call:
  # contour packs reproducibly — entries sorted, timestamps fixed at the zip
  # epoch — so an untouched tree keeps its hash and devices do not re-download
  # bytes they already have. It checks the layout BEFORE writing anything, and
  # warns when an archive looks drop-in-only.
  #
  # {base} is the only part a provider migration touches. Keeping {sha256} in
  # the path makes the URL content-addressed, so the same bytes keep the same
  # suffix on every host and a stale copy cannot masquerade as the new one.

  result = contour profile ddm service-config build {source_dir} \
                --service {service_type} \
                --base-url {base}                 \
                --org {org} -o {output_dir}       \
                [--predicate "..."]               \
                [--url-template 'https://{base}/{sha256}/{name}'] \
                --write --json

  if result.exit_code != 0:
    switch result.error_code:
      ARCHIVE_LAYOUT        -> restage: the tree mirrors / , e.g. {dir}/etc/ssh/...
      UNKNOWN_SERVICE_TYPE  -> fix the typo; the error names the closest match
      INVALID_ORG           -> supply --org
      HALT otherwise

  # Omitting --base-url is legal: the archive must exist before it can be
  # uploaded. DataURL then carries REPLACE-WITH-HOSTING-BASE and every run says
  # so. Upload, then `rehost` with the real base.

STEP 4 — Read the warnings, do not skip them:
  # "archive has no etc/ssh/sshd_config" means the service will see ONLY this
  # archive and none of its default directory. Almost always a mistake.
  # "not a service Apple documents" means files are delivered but nothing reads
  # them unless the service opts in — see THIRD_PARTY_SERVICES.

STEP 5 — Upload the archive to {base} at the path the DataURL names.

STEP 6 — Verify before deploying:
  ASSERT result.files contains the asset and the configuration
  ASSERT asset.Payload.Reference["Hash-SHA-256"] == result.sha256
  ASSERT configuration.Payload.DataAssetReference == asset.Identifier
  ASSERT the uploaded object is byte-identical to {output_dir}/{name}.zip

  RETURN {
    archive: result.archive,
    sha256: result.sha256,
    files: result.files,
    deploy_order: [asset, configuration, activation?],
  }
```

**Deploy order is asset first, then configuration.** A configuration whose
asset is absent cannot resolve its reference.

A configuration is inert without an activation. Add one when the files should
apply conditionally; see `--sop ddm` for predicates and the subscription rule.

---

## PROCEDURE move_hosting(output_dir, new_base)

The artifact is not recreated — only the asset that says where it lives. Use
this when files migrate between providers: Azure Blob Storage today,
Cloudflare tomorrow.

```
INPUT:
  output_dir : directory holding the declarations and .contour-service-config.toml
  new_base   : new hosting base, e.g. cdn.example.org/ddm

STEP 1 — Upload the SAME archives to the new host.
  # URLs are content-addressed, so the path after the base is unchanged.
  # Doing this first means the new URL resolves the moment it is deployed.

STEP 2 — Re-point, dry run first:
  contour profile ddm service-config rehost {output_dir} --base-url {new_base}

  # Rewrites Payload.Reference.DataURL from the recorded template.
  # Hash-SHA-256 is asserted, never written: a move cannot become a republish.
  # Re-running against the base already in use is a no-op — it must not mint a
  # new ServerToken and make the fleet re-download what it has.

STEP 3 — Apply, verifying the content did not drift along the way:
  contour profile ddm service-config rehost {output_dir} --base-url {new_base} \
       --verify --write

  # --verify re-packs each staged source and refuses with CONTENT_MOVED if its
  # hash differs from the index. Use it whenever the sources are present; the
  # flag is what separates "the files moved" from "the files changed".

  if error_code == CONTENT_MOVED:
    # This is a republish wearing a move's clothes. Run `build` instead — it
    # re-packs, re-hashes and re-points in one step.
    HALT

STEP 4 — Deploy the changed asset declarations.
  # The configuration is untouched: it references the asset by identifier,
  # which did not change.
```

## PROCEDURE update_content(output_dir, source_dir)

A config file was edited. Re-run `build` with the same arguments: it re-packs,
produces a new hash, writes a new URL and updates the index. Unchanged trees
produce an identical archive, so running it when nothing changed is safe.

Deploy the asset first, then the configuration — the device re-downloads when
the declaration's ServerToken changes.

---

## THIRD_PARTY_SERVICES

A `ServiceType` outside Apple's list delivers files; whether anything reads
them depends on the app.

- **The app calls the API.** `mcf_service_path_for_service_type` in
  `libmanagedconfigurationfiles.dylib` returns the managed directory for a
  service type. Apple's own sshd and CUPS do this; a reference Swift shim is at
  `boberito/managedConfigFiles`. This is the correct path, and the one to ask
  a vendor for.
- **A local action bridges it.** Symlink the app's expected config path at the
  managed file. This works and has been used to make Cisco Secure Client's XML
  configuration declarative.

**Caveat to state before recommending the bridge:** managed files are mode
`444` and SIP-protected. An app that writes its own configuration back will
fail against them. Test the specific app before fleet deployment.

When an agent proposes a third-party service type, it MUST say which of the two
mechanisms will read the files. "The files are delivered" is not the same as
"the app is configured."

---

## TRAPS

| Trap | Symptom | Guard |
|---|---|---|
| Archive not rooted at `/` | Declaration Verified, service unchanged | STEP 1 layout assert |
| Drop-in only | Service loses its main config; possible lockout | STEP 2 warning |
| Mutable URL | Cannot tell stale from current | STEP 4 immutable pin |
| Re-packed unchanged tree | Fleet-wide re-download of identical bytes | STEP 3 deterministic pack, refresh hash compare |
| Missing activation | Nothing applies | `--sop ddm` |
| Unsupervised target | Declaration rejected | precondition |

---

## COMMAND REFERENCE

```
contour profile ddm service-config build <dir> --service <type> [--base-url B]
       [--url-template T] [--intent NAME] [--predicate P] [--no-subscriptions]
       [--org D] [-o DIR] [--write]

contour profile ddm service-config rehost <decl-dir> --base-url B
       [--verify] [--write]
```

Both are dry-run by default. The index, `.contour-service-config.toml`, is
contour's bookkeeping — commit it beside the declarations; it is never shipped
to a device.
