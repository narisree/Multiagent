---
description: Popularity-based judgment for proposing local libraries
---

# Library judgment

## Use without asking

Popular mainstream libraries for the domain: `re`, `json`, `csv`, `pathlib`, `sys`, `datetime`, `collections`, `argparse`, `pydantic`, `pytest`, `jsonschema`.

## Ask first

- Niche packages with low download counts.
- Single-author packages without a recognized organization.
- Anything where the name resembles a popular package (typosquatting risk).
- Security-sensitive domains (cryptography, authentication).
- Native binaries or system-level CLIs not already on the machine.

When asking: "I'd suggest [package] for [purpose]. It has [X] weekly downloads on PyPI and is maintained by [org]. OK to use?"
