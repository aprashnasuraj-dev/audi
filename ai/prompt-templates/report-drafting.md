# Prompt Template: Report Drafting From Verified Evidence

```
Draft a confidential Minly VDP report only from the supplied human-verified evidence.
Do not invent impact. Do not promote scanner output.

Required:
- title in the form: [bug class] in [component] allows [specific unauthorized result]
- target: Minly Website / Android App / iOS App
- exact location
- concise summary
- vulnerability details
- numbered steps to reproduce
- minimal redacted request/response or visual proof
- "As an attacker, I could..." impact statement
- limitations
- suggested remediation
- retest criteria

Reject the draft if evidence touches uncontrolled user data, includes secrets, or describes only an out-of-scope best-practice issue.
```
