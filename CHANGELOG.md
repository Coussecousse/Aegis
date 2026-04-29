# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

- CI workflow behavior for early scaffold stage:
	- tolerate empty critical test collection
	- skip coverage gate when no tests are present yet
- Dev dependency versions updated:
	- `pytest` from 8.3.3 to 9.0.3
	- `pytest-asyncio` from 0.24.0 to 1.3.0

### Fixed

- Replaced invalid `actions/upload-artifact` reference in CI workflow.

### Security

- Resolved `pip-audit` failure caused by a known vulnerability in `pytest` 8.3.3.

## [0.1.0] - 2026-04-29

### Added

- Initial project scaffold
- CI pipeline
- Pre-commit hooks
- Contribution guidelines
