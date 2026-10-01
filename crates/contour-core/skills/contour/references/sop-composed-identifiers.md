# SOP: Composed identifiers

Nine keys across Apple's schema identify an app, extension or network
provider by a **composed identifier** — a bundle ID with signing evidence
attached. The evidence comes in two spellings that are not interchangeable,
and the platform decides which one applies. Get it wrong and the document
validates, deploys, reports **Verified**, and matches nothing.

Every format sentence below is quoted from Apple's own schema prose
(`apple/device-management`) and cross-checked against
`developer.apple.com/documentation/devicemanagement`.

## THE TWO SPELLINGS

```
"Bundle-ID (Team-ID)"                  parentheses — the team identifier
"Bundle-ID {Designated-Requirement}"   braces      — the full requirement string
```

Apple, on the requirement form:

> "Designated-Requirement" is the designated requirement string the device
> uses to match the code signature of the app. The device only applies
> defaults for an app if its code signature matches the composed identifier.

A **Team-ID** is five-to-ten characters from the leaf certificate. A
**designated requirement** is a predicate over the whole certificate chain —
`codesign -d -r-` prints it, and it cannot be reconstructed from a template:
only 19 of 55 locally scanned apps reproduce from the canonical Developer ID
shape. Read it; never compose it by hand.

## THE REGISTRY

Rendered from `contour_form::composed::REGISTRY` — the same table the
validator's `composed-identifier` rule reads. A test fails when this block
and the code differ, so edit the code, then paste what the test prints.
"Apple says" is the sentence from the key's own description in
`apple/device-management`.

<!-- registry:generated:begin -->
| Declaration | Key | Position | Form | Bare OK | Off macOS | Apple says |
|---|---|---|---|---|---|---|
| `app.settings` | `Privacy.PermissionDefaults` | the dictionary key | **DR `{…}`** | no | bare bundle ID | In iOS, the app identifier is a bundle ID, for example, "com.example.app". In macOS, the app identifier is a composed identifier. The format of the composed identifier is "Bundle-ID {Designated-Requirement}". |
| `webcontent-filter.plugin` | `Filter.Sockets.ProviderComposedIdentifier` | value | **DR `{…}`** | no | bare bundle ID | In iOS and visionOS, the identifier is a bundle ID, for example, "com.example.app". In macOS, the identifier is a composed identifier. The format of the composed identifier is "Bundle-ID {Designated-Requirement}". |
| `webcontent-filter.plugin` | `Filter.Packets.ProviderComposedIdentifier` | value | **DR `{…}`** | no | unstated | The identifier is a composed identifier. The format of the composed identifier is "Bundle-ID {Designated-Requirement}". |
| `webcontent-filter.plugin` | `Filter.URLs.Parameters.ProviderComposedIdentifier` | value | **DR `{…}`** | no | bare bundle ID | In iOS, the identifier is a bundle ID, for example, "com.example.app". In macOS, the identifier is a composed identifier. The format of the composed identifier is "Bundle-ID {Designated-Requirement}". |
| `network.dns-proxy` | `ProviderComposedIdentifier` | value | **DR `{…}`** | yes | bare bundle ID | In iOS and visionOS, the identifier is a bundle ID, for example, "com.example.app". In macOS, the identifier is a composed identifier. The format of the composed identifier is either "Bundle-ID" or "Bundle-ID {Designated-Requirement}". |
| `network.vpn.vpn-plugin` | `Provider.ComposedIdentifier` | value | **DR `{…}`** | yes | bare bundle ID | In iOS, tvOS, and visionOS, the identifier is a bundle ID, for example, "com.example.app". In macOS, the identifier is a composed identifier. The format of the composed identifier is either "Bundle-ID" or "Bundle-ID {Designated-Requirement}". |
| `app.managed` | `AppComposedIdentifier` | value | **Team `(…)`** | yes | either form | The format of the composed identifier is either "Bundle-ID" or "Bundle-ID (Team-ID)". For example, "com.example.app" for the bundle ID format, or "com.example.app (ABCD1234)" for the team ID format. |
| `app.managed` | `ExtensionConfigs` | the dictionary key | **Team `(…)`** | yes | either form | A dictionary mapping extension composed identifiers to the extension config data and credentials. The format of the composed identifier is either "Bundle-ID" or "Bundle-ID (Team-ID)". |
| `extensible-sso` | `ExtensionComposedIdentifier` | value | **Team `(…)`** | no | bare bundle ID | In iOS and visionOS, the identifier is a bundle ID, for example, "com.example.app.sso-extension". In macOS, the identifier is a composed identifier. The format of the composed identifier is "Bundle-ID (Team-ID)". |
| `safari.extensions.settings` | `ManagedExtensions` | the dictionary key | **Team `(…)`** | yes, and `"*"` | composed too | Each key in the dictionary represents a composed identifier for a specific managed extension, or you can specify a single "*" character to match any extension. The composed identifier of a managed extension uses the format "Identifier (TeamIdentifier)", for example "com.example.app (ABCD1234)". […] For other platforms, request this information from the app developer. |
<!-- registry:generated:end -->

`safari.extensions.settings` makes the distinction load-bearing: `Allowed`
and `PrivateBrowsingAllowed` apply only when the key **is** a composed
identifier, not a bare one — and a single `"*"` key is Apple's documented
wildcard for any extension.

## PLATFORM IS THE DECIDER

The composed form is a **macOS** construction. Apple, on
`Privacy.PermissionDefaults`:

> In iOS, the app identifier is a bundle ID, for example,
> "com.example.app".
>
> In macOS, the app identifier is a composed identifier. […] For example,
> "com.example.app {anchor apple generic}".

Apple's own examples ship both: `example1.json` (iOS) keys by
`"com.example.scanner"`; `example2.json` (macOS) keys by
`"com.example.scanner {anchor apple generic}"`. `network.dns-proxy` says the
same for iOS **and visionOS**.

So a bare bundle ID is not "less specific" — on macOS it is wrong, and on
iOS a composed identifier is wrong. One declaration cannot serve both
platforms for these keys.

## PROCEDURE compose_identifier(app_path, key, target_platform)

```
PRECONDITIONS:
  ASSERT key IS IN the registry above
    ELSE  it is an ordinary string key; stop — this SOP does not apply

  ASSERT app_path exists on THIS machine
    HALT "the designated requirement is read from the installed app;
          {app_path} is not present. Install it, or obtain the
          requirement from a machine that has it."

STEPS:
  1. READ identity ← contour app manifest {app_path}
       → bundle_id, team_id, designated_requirement  (provenance: observed)

  2. SELECT form:
       target_platform == macOS AND registry[key].form == DR
         → "{bundle_id} {{{designated_requirement}}}"
       registry[key].form == Team
         → "{bundle_id} ({team_id})"
       target_platform IN {iOS, iPadOS, tvOS, visionOS, watchOS}
         → "{bundle_id}"                      ← bare; composed is macOS-only
       registry[key].bare_ok AND no signing evidence available
         → "{bundle_id}"  AND WARN "matches any signature of this bundle ID"

  3. NEVER hand-write the requirement. NEVER shorten it. NEVER substitute
     the team ID for it — a requirement is a chain predicate, a team ID is
     one field of one certificate.

POSTCONDITIONS:
  ASSERT braces form matches /^\S+ \{.+\}$/
  ASSERT parens form matches /^\S+ \([A-Z0-9]{5,12}\)$/
  ASSERT the emitted requirement is byte-identical to `codesign -d -r-`
```

## WHAT CONTOUR DOES

```bash
contour app manifest /Applications/Privileges.app        # read identity
contour profile form emit com.apple.configuration.app.settings \
  --values values.json --org com.acme --intent privileges --os macos
```

`form emit` and `ddm validate` apply one rule, `composed-identifier`, to all
nine keys from the registry above. **With a target platform the wrong
spelling is refused**: `--os macos` refuses a bare bundle ID where Apple
documents only the composed form, and `--os ios` refuses a composed
identifier where Apple documents a bare one — because either produces a
declaration that reports Verified and matches nothing. Where Apple accepts
the bare form it warns instead, saying what a bare ID matches. Without a
target, contour says which platform each form is for rather than guessing.

## TRAPS

| Trap | Symptom | Guard |
|---|---|---|
| Bare bundle ID on macOS | Declaration Verified; no permission applied | `--os macos` warns; `app manifest` supplies the requirement |
| Composed identifier on iOS | Same, silently | `--os ios` warns |
| Team ID substituted for a requirement | Matches a different app from the same vendor | Registry above: the two forms are different keys, not styles |
| Parentheses around a requirement | Matches nothing | Named separately — the requirement *is* there, the delimiter is wrong |
| Requirement copied from another machine's build | Matches until the app updates | `provenance: observed` records where it was read |
| Requirement retyped by hand | Matches nothing; no error anywhere | Never hand-write it — step 3 |

## RELATED

- `--sop app-privacy` — the `PermissionDefaults` workflow end to end
- `--sop pppc` — `CodeRequirement` in TCC payloads, same string, different key
- `--sop santa` — `TeamID` / `SigningID` / `CDHash` binary rules
- `docs/contour-app-manifest.md` — where the identity comes from
