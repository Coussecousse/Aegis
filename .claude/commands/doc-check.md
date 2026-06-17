# doc-check — Documentation Freshness Review

Run this before every commit that touches code, config, or env vars.
Check each file below and update it if the change affects it.

## Files to review

1. **README.md** — feature list, quickstart, env var table
   - New feature added? Add it to the feature list.
   - New `make` target? Add it to the quickstart.
   - New env var read by the code? Add it to the env var table.

2. **Makefile** — targets and help text
   - New script or compose file? Add a corresponding `make` target with a `##` help line.
   - Changed compose file path or env file location? Update the target.

3. **docs/runbooks/poc-linux-startup.md** — POC steps and known issues
   - New LDAP/connector env var? Update Étape 4 and Prerequisites.
   - New known issue found during testing? Add it to Troubleshooting.
   - Changed a command or workflow? Update the relevant step.

4. **.env.example** — template for all env vars
   - New env var read by any Python module? Add it with a placeholder value and a comment.

5. **docs/ files for the changed component** — e.g., ADRs, setup guides
   - Changed an architecture decision? Write or update the ADR.

## Commit rule

If any of the above needed updating: create a **separate** `docs(...)` commit.
If none needed updating: add this line to the code commit body:
`Docs: no update needed`
