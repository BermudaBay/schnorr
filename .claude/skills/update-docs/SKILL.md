---
name: update-docs
description: Update README after a significant change. Only for new features, changed API, or architectural shifts — not bug fixes or refactors.
allowed-tools: Read Write Edit Grep Glob Bash(git diff*)
---

# Update README

Only for **significant** changes. Skip bug fixes, refactors, test-only changes.

## Step 1: Check if Update is Needed

```sh
git diff main --stat
git log main..HEAD --oneline
```

If the changes don't affect public API, features, or build/setup — stop here.

## Step 2: Update README.md

Read README.md and compare against the new implementation:
- Feature **adds** something → add or extend the section
- Feature **changes** how something works → **rewrite** the affected sections to match
- Feature **removes** something → remove the corresponding docs

Also update CLAUDE.md if build commands, file structure, or key exports changed.
