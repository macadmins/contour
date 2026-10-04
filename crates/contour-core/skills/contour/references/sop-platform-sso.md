# SOP: Platform SSO (DDM)

**Scope: Platform SSO on macOS 27, delivered as the `com.apple.configuration.extensible-sso`
declaration** — IdP-backed login, unlock and FileVault policies, Touch ID and Apple
Watch requirements, Authenticated Guest Mode, and Tap to Login with an access key.

> **Not this SOP:** generic DDM mechanics (`--sop ddm`), Apple Intelligence
> (`--sop generative`), or the SSO extension itself — the IdP vendor ships that.

Four scenarios ship as presets. Start from the preset; author by hand only when none
fits. Every "Only use when …" and "Required when …" sentence Apple attaches to these
keys is a cross-key rule in contour: `compose`, `generate` and `validate` refuse a
wrong combination and name both keys, joined by `↔`.

Format spec: `crates/contour-core/skills/contour/references/sop-format-spec.md`
Companion SOPs: `--sop ddm` (compose, bundles, presets), `--sop composed-identifiers`
(the `ExtensionComposedIdentifier` value).

## THE PLATFORM SSO KEY MAP

```
com.apple.configuration.extensible-sso
  ExtensionComposedIdentifier          # the IdP's SSO extension: "bundle.id (TEAMID)" — yours, no default
  Type                                 # Redirect (OIDC) | Credential (Kerberos)
  URLs[]                               # Redirect: the IdP endpoints the extension handles
  PlatformSSO
    AuthenticationMethod               # Password | UserSecureEnclaveKey | SmartCard | OpenID
    UseSharedDeviceKeys                # true is REQUIRED for EnableAtLogin and EnableIdentityProviderAccounts
    LoginFrequency                     # seconds until a full login; minimum 3600
    RegistrationToken                  # silent registration; needs AuthenticationMethod
    UserCreation
      EnableAtLogin                    # create the account at the login window (Password or SmartCard)
      NewUserAuthorizationMode         # Standard | Admin | Groups | Temporary (= Authenticated Guest Mode)
      NewUserAuthenticationMethods[]   # Password | SmartCard | AccessKey (= Tap to Login) | OpenID
      TemporarySessionQuickLogin       # guest mode: wipe select locations per session, all every 8h
    AccessKey                          # Tap to Login; all three REQUIRED when methods include AccessKey
      ReaderGroupIdentifier            # Data: the badge system's reader group, base64
      TerminalIdentityAssetReference   # → credential.identity | .scep | .acme asset
      ReaderIssuerCertificateAssetReference  # → credential.certificate asset (elliptic-curve key)
      AllowExpressMode                 # tap alone, no PIN/biometric on the badge
    Policies
      Login[] / Unlock[] / FileVault[] # AttemptAuthentication | RequireAuthentication
                                       # | AllowOfflineGracePeriod | AllowAuthenticationGracePeriod
                                       # | RequireTouchID | RequireTouchIDOrWatch | AllowOpenIDForTouchIDFallback
                                       # | AllowTouchIDOrWatchForUnlock (Unlock only)
      OfflineGracePeriod               # REQUIRED when a list has AllowOfflineGracePeriod
      AuthenticationGracePeriod        # REQUIRED when a list has AllowAuthenticationGracePeriod
      NonPlatformSSOAccounts[]         # local accounts exempt from the policies
```

## SCENARIO → PRESET

| Ask | Preset | Edit before composing |
|---|---|---|
| IdP login required everywhere, with grace periods | `platform-sso-baseline` | `ExtensionComposedIdentifier`, `URLs` |
| Touch ID at every login and unlock, password always | `platform-sso-touchid` | same |
| Authenticated Guest Mode (cloud user, no local account, wiped at logout) | `platform-sso-guest-mode` | same |
| Tap to Login (NFC badge/phone opens a guest session) | `platform-sso-tap-to-login` | same + `AccessKey.ReaderGroupIdentifier` + two asset identifiers |

```
contour profile ddm compose --list-presets --json     # the four, with descriptions
```

## PROCEDURE platform_sso_from_preset(preset, org, output)

```
SCHEMA_TOOL: contour profile ddm info com.apple.configuration.extensible-sso --full --json
             contour profile ddm compose --list-presets --json

PRECONDITIONS:
  ASSERT preset in {platform-sso-baseline, platform-sso-touchid,
                    platform-sso-guest-mode, platform-sso-tap-to-login}
  ASSERT the IdP's SSO extension composed identifier is known
    HALT "ask the operator which IdP (Microsoft Company Portal, Okta Verify, …);
          the composed identifier is theirs — see --sop composed-identifiers"

STEP 1 — Compose:
  contour profile ddm compose --preset {preset} --org {org} -o {output} --json
  # → configuration.json + activation.json

STEP 2 — Replace the placeholders in {output}/configuration.json:
  Payload.ExtensionComposedIdentifier   ← the IdP extension, "bundle.id (TEAMID)"
  Payload.URLs                          ← the IdP endpoints
  (tap-to-login only)
  Payload.PlatformSSO.AccessKey.ReaderGroupIdentifier          ← base64 from the badge system
  Payload.PlatformSSO.AccessKey.TerminalIdentityAssetReference ← Identifier of the identity asset
  Payload.PlatformSSO.AccessKey.ReaderIssuerCertificateAssetReference ← Identifier of the CA asset
  # A value still reading com.example / AAAA… is not deployable.

STEP 3 — (tap-to-login only) Create the two assets beside the configuration:
  contour profile ddm generate com.apple.asset.credential.identity \
      --identifier {org}.asset.psso-terminal-identity --org {org} -o {output}/terminal-identity.json
  contour profile ddm generate com.apple.asset.credential.certificate \
      --identifier {org}.asset.psso-reader-ca --org {org} -o {output}/reader-ca.json
  # then set each asset's Payload.Reference.DataURL to where the file is hosted.

STEP 4 — Validate and verify:
  contour profile ddm validate {output} --json       ASSERT every entry valid
  contour profile ddm verify   {output} --json       ASSERT 0 errors (no dangling asset reference)

POSTCONDITIONS:
  SWITCH entry.error_code
    CASE SCHEMA_VIOLATION: the error names the two keys in conflict ("A ↔ B: …")
                           and quotes Apple's rule; fix the named key, do not loosen the other
    DEFAULT: HALT
  RETURN { configuration, activation, [assets] }
```

## PROCEDURE platform_sso_custom(values, org, output)

When no preset fits: author `values.json` with only the keys intent needs and let
the schema fill the rest.

```
contour profile ddm generate com.apple.configuration.extensible-sso \
    --payload values.json --org {org} -o {output}/extensible-sso.json --json
contour profile ddm validate {output}/extensible-sso.json --json
```

INVARIANTS the rules enforce (each message: `key ↔ key: rule (found …) — Apple: "…"`):

```
AttemptAuthentication, RequireAuthentication, AllowAuthenticationGracePeriod,
AllowTouchIDOrWatchForUnlock          → AuthenticationMethod Password
RequireTouchID, RequireTouchIDOrWatch,
AllowOpenIDForTouchIDFallback         → AuthenticationMethod Password or UserSecureEnclaveKey
AllowOfflineGracePeriod               → Password with RequireAuthentication in the same list, or OpenID
AllowTouchIDOrWatchForUnlock          → RequireAuthentication in the same list
AllowOfflineGracePeriod set           → Policies.OfflineGracePeriod present
AllowAuthenticationGracePeriod set    → Policies.AuthenticationGracePeriod present
EnableAtLogin, EnableIdentityProviderAccounts → UseSharedDeviceKeys true
EnableAtLogin                         → AuthenticationMethod Password or SmartCard
RegistrationToken                     → AuthenticationMethod set
LoginFrequency                        → ≥ 3600
NewUserAuthenticationMethods ∋ AccessKey → all three AccessKey keys present,
                                            NewUserAuthorizationMode Temporary, EnableAtLogin true
```

## SAFETY

- `RequireAuthentication` with no grace period locks out every account the IdP
  cannot vouch for, offline too. Stage through a cohort; keep a local admin in
  `NonPlatformSSOAccounts` until registration is confirmed.
- Guest mode and Tap to Login wipe the home folder at logout. Say so to the people
  who will use the Mac.
- `AllowExpressMode = true` lets the tap alone log in — no PIN or biometric on the
  badge. Leave it false unless the badge system enforces its own.
- The two IdP identifiers named in the preset headers (Microsoft, Okta) come from
  the vendors' documentation at the time of writing; confirm before shipping.

## Key flags

- `compose --preset <name>` / `--list-presets`; `--preset-path <dir>` for a local library.
- `generate --payload <file>` to author from values; `--identifier` to name a declaration.
- `validate <dir|file> --json`; `verify <dir> --json` for cross-references.
