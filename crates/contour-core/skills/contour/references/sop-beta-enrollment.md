# SOP: Beta enrollment (AppleSeed for IT) declarations

Enroll (or block) devices in Apple beta programs through
`com.apple.configuration.softwareupdate.settings`. The declaration is one
command; the **seeding tokens it needs come from Apple** through a manual
Apple Business/School Manager round-trip that no tool can shortcut.

This SOP is written so an agent can drive it: the automatable steps are
commands, the manual steps are explicit gates with a named artifact to wait
for, and the workflow resumes as soon as that artifact exists.

Companion SOPs: `--sop ddm` (declarations generally), `--sop beta`
(pre-release *schema* channel — a different thing entirely).

---

## Decide the outcome first

```
What should devices do about beta programs?
│
├─ Users may self-enroll with their own Apple Account, and I also
│  want to offer org programs        → --mode offer      (Allowed)
│
├─ Only my programs; users must not self-enroll, but may choose
│  from the list I publish           → --mode always-on  (AlwaysOn)
│
├─ Devices go into exactly one program, automatically
│                                    → --mode require    (AlwaysOn + RequireProgram)
│
└─ No beta at all; pull devices out of any program they are in
                                     → --mode block      (AlwaysOff)
```

`offer`, `always-on` and `require` need tokens. `block` does not — it is the
one mode you can ship immediately.

### One platform per declaration

Apple issues **one token per OS and release** (`macOS 27 Golden Gate`,
`iOS 27`, `tvOS 27`, `visionOS 27`, `watchOS 27`, `HomePod 27`, …). A device
only enrols with a token for **its own OS**, so a single declaration must not
mix platforms — contour refuses that combination and names the fix.

Several *releases of the same OS* in one declaration are fine and expected
(that is what `OfferPrograms` is for: macOS 26 and macOS 27 side by side).

```bash
# One declaration per platform, from the full ABM token list
contour profile ddm beta --mode always-on --tokens tokens.json \
  --split-by-os --org com.acme -o per-os/
# → per-os/beta-macos.json     com.acme.settings.macos    (both macOS releases)
#   per-os/beta-ios.json       com.acme.settings.ios
#   per-os/beta-tvos.json      com.acme.settings.tvos      … one per OS

# Or pick interactively (labels show the platform of each program)
contour profile ddm beta --mode offer --tokens tokens.json \
  --interactive --org com.acme -o beta-macos.json
```

Identifiers are suffixed per platform (`<base>.macos`, `<base>.tvos`) so the
declarations do not overwrite each other. Scope each to the matching device
group in your MDM.

---

## PROCEDURE build_beta_declaration(mode, org)

```
INPUT:
  mode          one of offer | always-on | require | block
  org           reverse-DNS org domain (or an explicit --identifier)
  tokens_file   path to the seeding tokens JSON  [not needed for block]

PRECONDITIONS:
  ASSERT mode ∈ {offer, always-on, require, block}
  IF mode == block:
      GOTO EXECUTION                      # no Apple artifact required
  IF tokens_file is absent OR does not exist:
      HALT → run PROCEDURE obtain_seeding_tokens (manual gate below),
             then resume here

EXECUTION:
  contour profile ddm beta --mode {mode} \
      [--tokens {tokens_file}] [--select {program}...] \
      --org {org} -o {output}.json

POSTCONDITIONS:
  SUCCESS  → declaration written; identifier + enrollment + programs echoed
  SWITCH error:
    CASE "missing beta seeding tokens"
         → the manual gate has not been completed; see obtain_seeding_tokens
    CASE "enrolls the device in exactly one program"
         → mode=require with several tokens; re-run with --select <program>
    CASE "no beta program matches"
         → --select value is not in the tokens file; the error lists valid names
    CASE "organization domain is required"
         → pass --org, set CONTOUR_ORG, or name it with --identifier

INVARIANTS:
  - Output always satisfies Apple's Beta cross-key rules (see below) — the
    command cannot emit an illegal combination by construction, and the
    fail-closed validator re-checks before writing.
  - Re-running with identical inputs produces an identical declaration.
```

## PROCEDURE obtain_seeding_tokens — **MANUAL GATE**

Apple issues seeding tokens; they cannot be generated locally. An agent must
stop here, state the steps, and wait for a human to produce the artifact.

```
MANUAL STEP 1 — MDM server record (human, in a browser)
  Generate a keypair; upload the public certificate to a NEW MDM server
  record: Apple Business/School Manager → Preferences → Your MDM servers.
  Download that server's token file (`.p7m`).
  ARTIFACT: <name>.p7m

MANUAL STEP 2 — decrypt the server token (scriptable, needs the private key)
  The .p7m is CMS *EnvelopedData* — encrypted, not merely signed — so it
  needs the private key that matches the uploaded certificate:

    openssl smime -decrypt -inform DER -in token.der \
      -recip mdm_public_cert.pem -inkey mdm_private.key -out server_token.json

  The plaintext holds the DEP OAuth credentials (consumer key/secret,
  access token/secret, expiry). Treat it as a secret: do not commit it, and
  delete the plaintext once the tokens are fetched.
  ARTIFACT: server_token.json   (short-lived)

MANUAL STEP 3 — fetch the seeding tokens (API, automatable)
  Authenticate to Apple's DEP API with those credentials and call:

    GET /os-beta-enrollment/tokens

  Response shape — save it verbatim:
    {"betaEnrollmentTokens":[{"title":"…","os":"OSX","token":"…"}, …]}
  ARTIFACT: tokens.json         ← the file build_beta_declaration waits for

RESUME: once tokens.json exists, return to build_beta_declaration.
```

**Agent guidance.** Running the command without `--tokens` prints exactly
these steps and exits non-zero (`MISSING_INPUT` in `--json`). That is the
designed handoff: surface the steps, let the human do STEP 1, then continue
automatically once the artifact appears. Do not fabricate tokens to get past
the gate — a placeholder token produces a declaration that installs and then
silently fails to enrol.

---

## Worked example

```bash
# tokens.json is the saved /os-beta-enrollment/tokens response

# Offer: users may self-enroll, plus both org programs
contour profile ddm beta --mode offer --tokens tokens.json \
  --org com.acme -o beta-offer.json

# Always-on: only org programs, no self-enrollment
contour profile ddm beta --mode always-on --tokens tokens.json \
  --org com.acme -o beta-alwayson.json

# Require: auto-enroll one named program
contour profile ddm beta --mode require --tokens tokens.json \
  --select "macOS 27 Public Beta" --org com.acme -o beta-require.json

# Block: no tokens needed at all
contour profile ddm beta --mode block --identifier com.acme.beta.block \
  -o beta-block.json
```

Deploy like any declaration: pair it with an activation
(`contour profile ddm compose`), and scope with your MDM.

---

## Apple's cross-key rules (contour enforces these)

| Rule | Meaning |
|---|---|
| `OfferPrograms` requires `ProgramEnrollment` ∈ {Allowed, AlwaysOn} | Cannot offer programs while beta is off |
| `RequireProgram` requires `ProgramEnrollment` = AlwaysOn | Auto-enroll only under full org control |
| `OfferPrograms` and `RequireProgram` are mutually exclusive | Either a menu or a mandate, never both |

`ddm validate` reports violations as errors — these are prose rules in
Apple's schema, so they are hand-encoded and only cover the types listed in
`cross_key_errors`. A declaration that breaks them installs and then
misbehaves on device, which is why they are errors rather than warnings.

`ProgramEnrollment` may be omitted entirely on unsupervised devices, where
Apple treats it as implicitly `Allowed`; contour permits that shape.

## Traps

- **Tokens are secrets.** They authorize beta enrolment for your org. Keep
  `tokens.json` out of git; inject at render time in CI.
- **The `.p7m` is encrypted, not signed.** `contour profile unsign` (which
  handles CMS *SignedData*) will not open it — you need the private key and
  `openssl smime -decrypt`.
- **`block` removes devices from programs they are already in** — that is a
  fleet-visible change, not a no-op.
- **Never mix platforms in one declaration.** contour blocks it, but if you
  hand-author the JSON the device silently fails to enrol — the token simply
  does not apply to that OS.
- **One declaration type, one settings surface.** `Beta` lives inside
  `softwareupdate.settings` alongside deferrals and automatic actions; if
  you already ship that declaration, merge the `Beta` object into it rather
  than deploying a second one (Apple's `apply` mode for this type is
  `combined`).

## Key flags

- `--mode` — offer | always-on | require | block (the desired outcome).
- `--tokens` — Apple's `/os-beta-enrollment/tokens` response, or a bare JSON
  array; `Description`/`Token` field names also accepted.
- `--select` — limit to named programs (by title or token); required for
  `require` when the file holds several.
- `--split-by-os` — emit one declaration per platform into `-o <DIR>`.
- `--interactive` — choose programs from a list (labels carry the platform).
- `--identifier` — name the declaration directly (no `--org` needed).
- `--json` — structured output for CI/agents.
