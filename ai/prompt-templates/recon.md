# Prompt Template: Low-Impact Recon Review

Use this prompt with a private AI assistant only after the current VDP scope has been confirmed.

```
You are reviewing sanitized Minly VDP recon output. Treat every automated signal as unverified.
Scope is exact-host `minly.com`, Android package `com.minly.users`, and iOS App Store ID `1528802350`.
Do not suggest subdomain expansion, high-volume scanning, ID enumeration, WAF evasion, social engineering, or third-party testing.

Given the attached sanitized surface map, produce:
1. interesting endpoints or object classes;
2. why each may represent an authorization/business-logic boundary;
3. the minimum safe manual Account A / Account B confirmation step;
4. evidence required before this could be called a finding;
5. reasons to discard scanner-only or best-practice noise.
```
