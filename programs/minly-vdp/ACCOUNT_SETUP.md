# Researcher-Controlled Account Setup

This phase uses exactly two ordinary Minly user accounts controlled by the researcher. Do not create celebrity, staff, moderator, business-admin, or elevated-role accounts.

## Account labels

Use opaque labels in notes and reports:

- **Account A** — first ordinary user account
- **Account B** — second ordinary user account

Do not commit real email addresses, phone numbers, passwords, session cookies, access tokens, recovery codes, payment details, or screenshots containing them to this public repository.

## Creation checklist

Create both accounts through Minly's normal registration flow using contact details you control.

For each account:

- use a different email address;
- use a different password;
- complete only the verification steps required by Minly;
- keep the account as a normal consumer/user role;
- avoid importing contacts or granting unnecessary device permissions;
- do not use another person's phone number or identity;
- do not enroll either account as a celebrity/talent account;
- do not add real payment details unless a specific manual test later requires a legitimate purchase and you intentionally choose to perform it.

## Safe test data convention

Use clearly synthetic, harmless values so objects can be attributed without exposing real personal information.

Suggested markers:

- Account A display/test marker: `Research-A`
- Account B display/test marker: `Research-B`
- Account A object note/title: `A-OWNED-TEST`
- Account B object note/title: `B-OWNED-TEST`

Do not place security-test payloads in fields visible to celebrities, staff, or other users. Keep test data benign.

## Baseline record

Record privately, outside the public repository:

- creation timestamp;
- platform used (web / Android / iOS);
- app version if mobile;
- locale/language;
- whether email/phone verification was required;
- whether MFA or device confirmation was offered;
- the account's visible user role;
- the normal post-login landing page.

Do not record authentication secrets.

## Readiness criteria

Authorization testing may begin only when:

1. both accounts can log in normally;
2. both are ordinary user accounts;
3. each account can independently create or own at least one harmless in-scope object or account setting;
4. no third-party service needs to be tested directly;
5. the current Minly VDP scope has been rechecked.

## Stop conditions

Stop immediately if a test unexpectedly exposes another real user's non-public information, requires privilege escalation beyond the two controlled accounts, or would require high-volume requests, service disruption, or interaction with an out-of-scope third party.
