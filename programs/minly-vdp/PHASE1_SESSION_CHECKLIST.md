# Phase 1 Session Checklist

Use this checklist for the first authorization-focused research session after Account A and Account B are created.

## Before login

- Recheck the current Minly VDP scope.
- Confirm website scope remains exactly `https://minly.com/` unless the program has changed.
- Confirm Android package remains `com.minly.users` and iOS App Store ID remains `1528802350` before mobile testing.
- Confirm no new program exclusions affect the planned test.
- Use a normal browser/device; do not launch high-volume automation.
- Start a private worklog outside this public repository.

## Account A baseline

1. Log in normally.
2. Record the visible account role.
3. Map profile and account settings.
4. Note which user-owned objects/features are actually present.
5. Create only harmless, reversible test state where needed.
6. Capture the minimum request metadata necessary to understand ownership boundaries.
7. Log out.

## Account B baseline

Repeat the same steps using Account B.

The two accounts should use equivalent benign test data where possible so differences are attributable to authorization rather than content.

## Build the object-pair table privately

For each feature that exists, create an A/B pair:

| Object class | Account A object exists | Account B object exists | Safe to cross-check? |
|---|---:|---:|---:|
| Profile | yes | yes | yes, read-first |
| Account settings | verify | verify | yes, read-first |
| Favorites/saved item | verify | verify | if feature exists |
| Draft/request | verify | verify | only if non-disruptive |
| Notification | verify | verify | if feature exists |
| Support ticket | verify | verify | only if low burden |
| Order/receipt | verify | verify | only with own legitimate orders |
| Wallet/credits | verify | verify | read-only first |
| Event entitlement | verify | verify | only with own entitlement |
| Purchased media | verify | verify | only own media |

Do not put live object identifiers in this public repository.

## First cross-account pass

For each safe object pair:

1. Confirm A -> A succeeds normally.
2. Confirm B -> B succeeds normally.
3. Perform one A-session request using only the controlled B-owned object reference, if the product request shape naturally exposes such a reference.
4. Perform the reverse only if needed to rule out account-specific behavior.
5. Record status code, high-level response type, and whether private content/state was returned or changed.
6. Stop on the first confirmed unauthorized private-data or state-changing result and prepare a report rather than expanding the test.

## Noise controls

Before classifying a difference as an authorization issue, check that it is not caused by:

- intentionally public profile data;
- localization;
- cached content;
- different account settings;
- feature flags;
- different object lifecycle state;
- expired sessions;
- payment/entitlement differences that are expected;
- third-party redirects.

## Do not do during Phase 1

- no identifier enumeration;
- no wordlists;
- no brute force;
- no mass endpoint discovery;
- no high request rates;
- no other-user identifiers;
- no destructive changes outside the two research accounts;
- no payment bypass testing;
- no celebrity/staff impersonation;
- no testing third-party payment, analytics, social, CDN, or app-store infrastructure.

## Phase 1 completion criteria

Phase 1 is complete when:

- two ordinary researcher-controlled accounts exist;
- the current web/mobile workflow map is confirmed;
- all low-risk user-owned object classes have been inventoried;
- safe A/B read-isolation checks have been performed manually;
- any candidate issue has been stopped at minimum proof and routed through the finding eligibility gate;
- untested higher-risk/paid flows are clearly recorded as coverage gaps rather than assumed secure.
