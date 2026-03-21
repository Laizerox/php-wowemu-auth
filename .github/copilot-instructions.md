# Copilot Instructions

## Project Overview

- This repository is a small PHP library that implements WoW emulator compatible SRP6 authentication helpers.
- The public API lives under the `Laizerox\\Wowemu\\SRP` namespace and is PSR-4 autoloaded from `src/`.
- Prefer small, targeted changes. This is a library, not an application.

## Read First

- [README.md](README.md) for installation and usage examples.
- [src/Wowemu/SRP/Client.php](src/Wowemu/SRP/Client.php) for shared SRP behavior.
- [tests/SRPClientIntegrationTest.php](tests/SRPClientIntegrationTest.php) for the end-to-end handshake sequence.
- [tests/UserClientTest.php](tests/UserClientTest.php) for verifier and salt expectations.

## Commands

- Install dependencies: `composer install`
- Run tests: `composer run-script test`
- Alternative direct test command: `vendor/bin/phpunit`

## Important Environment Constraints

- PHP 8+ is required by `composer.json`.
- The `ext-bcmath` extension is required.
- Cryptographic big integer operations are implemented through `phpseclib/phpseclib` v2.
- In interactive `zsh`, `composer test` may trigger shell autocorrect (`test` -> `tests`). Use `composer run-script test` to avoid that prompt.

## Code Map

- `src/Wowemu/SRP/Client.php`: abstract base class for shared SRP state, proofs, and random value generation.
- `src/Wowemu/SRP/UserClient.php`: client-side registration and login computations, including salt and verifier generation.
- `src/Wowemu/SRP/HostClient.php`: host/server-side session computation and client proof validation.
- `tests/`: PHPUnit coverage for verifier generation and a complete client/host exchange.
- `.github/workflows/php.yml`: CI matrix and canonical test workflow.

## Working Conventions

- Preserve the existing namespace structure and public method names unless the task explicitly requires an API change.
- Keep SRP math changes minimal and grounded in the existing protocol flow. If you change session, proof, salt, verifier, or ephemeral value logic, update or extend integration coverage.
- Match the existing PHPUnit 13 style that uses PHP attributes such as `#[DataProvider]`.
- Follow existing coding style in touched files; do not reformat unrelated code.

## Testing Expectations

- For behavior changes in SRP calculations or validation, run the full PHPUnit suite.
- Prefer adding assertions to the existing tests before creating new test structure when the scenario fits current coverage.
- Use [tests/SRPClientIntegrationTest.php](tests/SRPClientIntegrationTest.php) as the reference for the intended client/host message order.

## Notes For Agents

- Do not duplicate long usage examples from [README.md](README.md); link to it instead.
- When investigating a bug, check whether it affects registration flow (`UserClient`) or handshake validation (`HostClient` + integration test) first.
