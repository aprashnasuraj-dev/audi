# Evidence Checklist

The goal is to prove impact with the minimum data necessary.

## Capture

- Exact in-scope asset and affected URL/screen/API operation.
- Date/time and app/browser version.
- Preconditions and researcher-controlled account role(s).
- Numbered reproduction steps.
- Expected security behavior.
- Actual behavior.
- Minimal request/response excerpts needed to prove the issue.
- Screenshot or short video where it materially improves reproducibility.
- Clear statement of demonstrated impact.
- Retest criterion for Minly.

## Redact before saving or submitting

Always remove or mask:

- passwords;
- access/refresh tokens;
- session cookies;
- API keys;
- OAuth codes/state values;
- phone numbers/emails unless they belong to your controlled test account and are necessary;
- unrelated account IDs;
- third-party user content;
- device identifiers not needed for reproduction.

## Privacy stop rule

If non-public information from another user becomes visible:

1. stop immediately;
2. do not continue navigating the data;
3. do not copy/download additional content;
4. retain only the minimum evidence already exposed, preferably redacted;
5. report promptly and explain that testing was stopped under the program rule.

## Proof quality

Good evidence answers all four questions:

1. **What boundary should have existed?**
2. **What exact action crossed it?**
3. **How do we know the result was unauthorized?**
4. **What real security consequence follows?**

Avoid submitting screenshots of scanner dashboards, generic header dumps, library-version lists, or configuration warnings without a manual exploit path and demonstrated Minly impact.
