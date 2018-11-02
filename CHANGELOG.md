# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- This CHANGELOG file.
- Property based tests powered by [stream_data].
- `SRP.Client` behaviour.
- `SRP.Server` behaviour.
- Function `generate_verifier/2`.
- Function `server_key_pair/2`.
- Function `client_key_pair/1`.
- Function `client_proof/5`.
- Function `valid_client_proof?/5`.
- Function `server_proof/5`.
- Function `valid_server_proof?/6`.
- Support all prime group from [RFC 5054].

[Unreleased]: https://github.com/thiamsantos/srp-elixir/compare/HEAD...HEAD
[stream_data]: https://hex.pm/packages/stream_data
[RFC 5054]: https://tools.ietf.org/html/rfc5054