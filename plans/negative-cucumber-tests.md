# Negative Cucumber Test Plan

## Goal

Add Cucumber/behave coverage proving wrong inputs fail, not only happy paths pass.

## Changes

- Add feature scenarios for wrong crypto behavior:
  - Text encrypted with one valid `crypto_key` cannot decrypt with another valid key.
  - Invalid image base64 cannot encrypt.
  - Image encrypted with one key cannot decrypt with another key.
- Add step definition to decrypt previous crypto response with replacement key.
- Run `uv run behave` and verify all scenarios pass.

## Acceptance

- New negative scenarios fail if service wrongly returns `200` for bad behavior.
- Existing positive scenarios still pass.
