# Confidentiality and Data Handling

This repository is public. Therefore **do not commit actual Minly vulnerability details, unpublished proof-of-concept material, credentials, session state, tokens, screenshots containing private data, or raw traffic captures** here.

## Keep private

Store the following outside this public repository until Minly explicitly permits disclosure:

- candidate vulnerability details;
- exact exploit parameters;
- access/session tokens and cookies;
- screenshots/videos containing account data;
- HTTP archives and proxy histories;
- unpublished report drafts;
- Minly triage correspondence;
- any evidence involving non-public data.

## Safe to keep here

- generic scope policy;
- generic test methodology;
- generic report templates;
- readiness checks that perform no live vulnerability testing;
- sanitized, non-target-specific examples.

## Disclosure rule

The program requires confidentiality until Minly confirms resolution/disclosure terms. Public GitHub commits are public disclosure, so real findings must not be pushed to this repository before that point.

## Accidental-data procedure

If a secret or unpublished finding is committed accidentally:

1. stop further sharing immediately;
2. rotate/revoke exposed credentials or session material where applicable;
3. remove the material from the current branch;
4. treat Git history as potentially exposed and perform history cleanup if necessary;
5. notify Minly if program-confidential vulnerability information was inadvertently disclosed.
