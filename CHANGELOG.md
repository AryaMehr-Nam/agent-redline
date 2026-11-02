# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Project foundation, architecture blueprint, and core domain models.
- Normalized `ToolCall`, `Verdict`, `Decision`, `ToolKind`, and `RiskLevel` dataclasses.
- TOML configuration loader with `audit`, `balanced` (default), and `strict` modes.
- Fallback-to-`ask` error handling strategy for internal evaluation safety.
