## Summary

<!-- Explain the WHY of this change first, then the WHAT. -->

## Related Issues

<!-- Example: Closes #123 -->

## Type of Change

- [ ] feat
- [ ] fix
- [ ] perf
- [ ] security
- [ ] chore
- [ ] docs
- [ ] test
- [ ] refactor
- [ ] ci
- [ ] revert

## Validation Checklist

- [ ] All pre-commit hooks pass (`pre-commit run --all-files`)
- [ ] Lint and type checks pass (`ruff check`, `mypy`)
- [ ] Tests pass and coverage does not drop below 80 %
- [ ] Critical path tests pass if touched (`@pytest.mark.critical`)
- [ ] No secret, key, token or credential introduced
- [ ] No outbound call to any cloud or external API introduced
- [ ] Wazuh CPU cap constraint respected if agent config was changed
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] PR targets `develop`, not `main`
- [ ] Description explains the **why**, not just the what

## Notes for Reviewers

<!-- Add implementation details, trade-offs, and any known limitations. -->
