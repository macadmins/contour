# SOP: Managed-Preference (MCX) Domain Rename

This SOP covers inspecting and renaming **managed-preference domains** with
`contour profile mcx list` and `contour profile mcx rename` — including the
guided `--interactive` flow, which picks the domain from what is actually in
the files rather than from a remembered string.

It is a surgical text edit, not a profile regeneration. For renaming *display
names* use `--sop profile-naming`; for rewriting `PayloadIdentifier`/UUIDs use
`profile reidentify`.

## When to use

- "Rename `de.example.legacy.*` to our new domain across these profiles"
- "What managed-preference domains are in this directory?"
- "Re-domain an MCX profile without reformatting the whole file"
- Vendor rename, org migration, or legacy-prefix cleanup of MCX payloads

## Why this is a separate operation

An MCX payload nests its settings under the preference domain as a dictionary
**KEY**, not a value:

```
com.apple.ManagedClient.preferences
  └── PayloadContent
        └── de.example.legacy.restrictions   ← the domain, a KEY
              └── Forced[] → mcx_preference_settings → { … }
```

contour's reference-rewriting (`normalize`, `reidentify`, `link`) deliberately
never touches keys, so none of it can re-domain an MCX profile. This command
can, and it does so by parsing to verify scope and then editing the raw XML at
exactly the `<key>…</key>` occurrences the parse accounted for. Everything else
in the file stays byte-for-byte — no plist round-trip, no reordered keys, no
unreviewable diff.

## The interactive flow

`--interactive` asks three questions, in order:

| Prompt | Widget | Default |
|---|---|---|
| `Domain to rename:` | select over every domain found, with occurrence counts | first entry |
| `Replace with:` | text, **pre-filled with the domain you picked** — edit it | the original |
| `Also rename sibling domains sharing this prefix?` | confirm | **yes** |

Read that third default carefully: accepting it widens the operation from one
domain to the domain plus all of its dot-separated children.

`--interactive` conflicts with `--from` and `--from-prefix`. It is not usable
in CI — scripted runs use the explicit modes below.

## Procedure

```
1. SURVEY — never rename against a remembered string
   contour profile mcx list <DIR> --recursive
   → every domain found, and which payload each sits in

2. DRY RUN (dry-run is the default — writes nothing)
   contour profile mcx rename <DIR> --recursive --interactive
   → answer the three prompts, then per file:
       ✓ /path/profile.mobileconfig
             de.example.legacy.dock  →  de.example.new.dock
     ends with "Dry run — no files written (pass --write to apply)"
     and "N file(s) affected, M refused"

3. REVIEW the preview. The domain list must match step 1, and no file may
   show ✗. Reconcile the affected count against `mcx list` — an unparseable
   profile is skipped silently and will not appear as a refusal.

4. APPLY — same command, plus --write (you answer the prompts again)
   contour profile mcx rename <DIR> --recursive --interactive --write
```

## Scripted (non-interactive) modes

```
# exact single domain
contour profile mcx rename <DIR> -r \
    --from de.example.legacy.dock --to de.example.new.dock --write

# a whole family, matched on dot boundaries
contour profile mcx rename <DIR> -r \
    --from-prefix de.example.legacy --to-prefix de.example.new --write
```

`--from` requires `--to`; `--from-prefix` requires `--to-prefix`. Passing
neither pair (and not `--interactive`) is an error.

## What "prefix" means

Prefix mode strips the prefix and requires the remainder to be empty or to
start with a dot:

- `de.example.legacy` → also renames `de.example.legacy.dock` ✅
- `de.example.legacy` → does **not** touch `de.example.legacyapp` ✅

In the interactive flow the prefix is always the domain you picked, so it
covers that domain and its children. It cannot match a *shorter* prefix than
what you picked — to rename a whole family from a common ancestor, use
`--from-prefix` explicitly.

## Refusals — it stops rather than half-writing

| Refusal | Meaning |
|---|---|
| `DomainNotPresent` | nothing matched in that file — **silently skipped**, normal in a mixed directory |
| `OccurrenceMismatch` | the raw XML holds a different count of `<key>domain</key>` than the parse accounted for; editing would touch something unverified |
| `TargetAlreadyPresent` | the target domain already exists in that payload — renaming would produce two identical keys and silently lose one settings set |

The parse-verification is what makes the text edit safe: a domain string can
also appear inside a *value* — a support path such as
`/Library/Application Support/com.acme.legacy/…` — and a blind substitution
would corrupt it.

Any refusal exits non-zero. If nothing matched anywhere at all:
`no file declared a matching domain — check the name against 'mcx list'`.

## Rules & cautions

- **Dry-run is the default.** `--write` is the only thing that touches disk.
- **A refusal does not roll back earlier files.** Files are written as the loop
  proceeds, so under `--write` a refusal on file 7 leaves files 1–6 already
  changed. "Nothing partial was written" is a per-file guarantee, not a
  per-run one — which is why step 2 dry-runs the whole set first.
- **Unparseable profiles are skipped silently**, not reported as refusals.
  Cross-check the affected count against `mcx list`.
- **An identical replacement errors out** rather than quietly doing nothing.
- **Signed profiles**: the rename edits raw XML, so re-sign afterward, and test
  on a copy first — a CMS-wrapped file does not present plain `<key>` tags to
  edit.
- **Renaming a domain changes what the profile manages.** The new domain must
  match the app's actual preference domain, or the settings apply to nothing.

## JSON shape (`--json`, scripted modes)

```json
{
  "success": true,
  "dry_run": true,
  "files_scanned": 12,
  "files_changed": 3,
  "changes": [
    { "file": "…/profile.mobileconfig",
      "renamed": [ { "from": "de.example.legacy.dock", "to": "de.example.new.dock" } ] }
  ],
  "refusals": []
}
```

`success` is false when any file refused. Error envelopes go to **stderr**;
stdout carries at most one JSON document per invocation.
