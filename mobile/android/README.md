# Android Deep Dive Workflow

Target package: `com.minly.users`.

Implemented path:

- provenance-checked public APK/XAPK fallback in `programs/minly-vdp/public_mobile_fallback.py`;
- static analysis through APKTool/JADX/MobSF/Semgrep/Gitleaks/Trivy in the corrected final audit workflow;
- local secret-scan wrapper in `mobile/secret-scanning/`;
- mobile findings remain candidates until direct Minly impact is reproduced manually.

Dynamic Frida/Objection work is lab-only and not executed in CI. Do not submit root-only, pinning-only, obfuscation-only, or local crash-only observations without backend/session/data impact.
