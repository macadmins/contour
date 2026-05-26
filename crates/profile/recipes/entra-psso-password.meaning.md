# entra-psso-password

MDM recipe sidecar — documents what this intent does, where it applies,
and where the authoritative spec lives. The listing description still
comes from the leading comment block of `entra-psso-password.toml`; this
file holds the deeper context that does not fit in a TOML header.

## Intent

Configures the Microsoft Entra ID SSO extension with Platform SSO using
the **Password** authentication method, so the local macOS account
password is kept in sync with the user's Entra ID password.

Password sync requires `PlatformSSO.AuthenticationMethod = "Password"` —
the Secure Enclave method (`entra-psso.toml`) is passwordless and has no
credential to sync. The recipe ships both account-creation paths so it
degrades gracefully across macOS versions:

- **macOS 26+** — `EnableRegistrationDuringSetup` +
  `EnableCreateFirstUserDuringSetup` register Platform SSO and create
  the first account inline during Setup Assistant (Automated Device
  Enrollment).
- **macOS 14–25** — older macOS ignores the two keys above and falls
  back to `EnableCreateUserAtLogin`, creating the account and syncing
  the password at the login window.

## Platforms

- [x] macOS
- [ ] iOS / iPadOS
- [ ] tvOS
- [ ] visionOS

`EnableRegistrationDuringSetup` and `EnableCreateFirstUserDuringSetup`
are macOS 26.0 APIs; `EnableCreateUserAtLogin` is macOS 14.0+.

## Apple defaults

Keys whose Apple-side default differs from this recipe — these are what
actually change behaviour when the profile applies:

- `AuthenticationMethod` — no default; **must** be set. `Password` is
  the only value that supports password sync.
- `EnableRegistrationDuringSetup` — defaults to `false`; set `true`.
- `EnableCreateFirstUserDuringSetup` — defaults to `false`; set `true`.
  Required *with* the Password method for the password to sync during
  Setup Assistant — registration alone does not sync.
- `EnableCreateUserAtLogin` — defaults to `false`; set `true` for the
  macOS 14–25 login-window fallback.
- `UseSharedDeviceKeys` — set `true` so all users share signing keys.

## Account-name mapping

`TokenToUserMapping.AccountName` is set to the sentinel value
`com.apple.PlatformSSO.AccountShortName`, **not** the raw
`preferred_username` claim. The sentinel tells the SSO extension to
use the **UPN prefix** (text before the `@`) as the macOS account
short name. `preferred_username` carries the full UPN
(`user@contoso.com`); an `@` is invalid in a short name, so the raw
claim stalls first-user creation during Setup Assistant.

Microsoft recommends the sentinel generally and **requires** it for
the `EnableCreateFirstUserDuringSetup` (ADE) flow this recipe enables.
`FullName` still maps to the `name` claim. Both `AccountName` and
`FullName` are free-form `<string>` subkeys in Apple's
`com.apple.extensiblesso` schema — the sentinel is a valid value, not
a separate key.

## Group-driven authorization (optional, off by default)

`EnableAuthorization` lets Entra group membership decide whether a PSSO
account is a local admin. It requires `UseSharedDeviceKeys = true`. The
recipe ships it commented out.

`UserAuthorizationMode` / `NewUserAuthorizationMode` accept `Standard`,
`Admin`, or `Groups` (`NewUserAuthorizationMode` also `Temporary`).
Only `Groups` consults group membership — `Standard`/`Admin` apply a
fixed privilege.

**Group identifiers are Entra group Object IDs (GUIDs), not display
names.** macOS matches each value in `AdministratorGroups` (admin) or
`AdditionalGroups` (non-admin) against the `groups` claim in the SSO
token, and that claim carries Object IDs:

- Find a group's Object ID: Entra portal → **Groups → _group_ →
  Overview → Object Id**, or `az ad group show --group <name> --query id`.
- Example: `AdministratorGroups = ["11111111-2222-3333-4444-555555555555"]`.

Two Entra-side requirements for `Groups` mode to work:

1. The enterprise app must be configured to **emit a group claim** in
   the token (Token configuration → Add groups claim).
2. Entra caps groups in a token at ~150. A user in more groups gets an
   **overage claim** instead of the list, and group authorization
   fails. Mitigate by filtering the claim to *"Groups assigned to the
   application"*.

## Deployment prerequisites

This profile is **one of three coordinated policies**. On its own it
only references the SSO extension — it does not install it.

1. This Platform SSO settings profile.
2. **Intune Company Portal 5.2604.0+** delivered as an app, before or
   alongside this profile. It provides the Enterprise SSO extension.
   If it is missing or arrives late, Setup Assistant shows an "Unable
   to sign in" error.
3. The ADE enrollment profile (Setup Assistant with modern
   authentication, await final configuration, locked enrollment).

All three must target the same enrolling users.

## References

- Apple device-management spec: <https://developer.apple.com/documentation/devicemanagement>
- Apple `com.apple.extensiblesso` PlatformSSO schema (key availability)
- Configure Platform SSO for macOS: <https://learn.microsoft.com/intune/device-configuration/settings-catalog/configure-platform-sso-macos>
- Add Platform SSO policy to ADE Profile on macOS: <https://learn.microsoft.com/intune/device-configuration/settings-catalog/configure-platform-sso-during-enrollment>
- PSSO registration during ADE (announcement): <https://techcommunity.microsoft.com/blog/intunecustomersuccess/new-platform-sso-with-registration-during-automated-device-enrollment-on-macos/4519846>
- Fleet issue #44867 — pSSO with Entra at the login window: <https://github.com/fleetdm/fleet/issues/44867>
- contour schema lookup: `contour profile info com.apple.extensiblesso --full`

## Generate example

```bash
contour profile generate \
    --recipe entra-psso-password \
    --org com.fleetdm \
    -o ./profiles
```
