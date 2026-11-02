# Security Policy

## Reporting Security Bypasses and Vulnerabilities

We welcome security research and bypass reports. `agent-redline` is designed as a defense-in-depth deterministic firewall, not a kernel-enforced sandbox.

### Where to Report
- **For routine rule bypasses (new shell trick, evasion syntax):**
  Open an issue using the [Bypass Report Template](.github/ISSUE_TEMPLATE/bypass-report.yml).
- **For severe or sensitive vulnerabilities:**
  Please email `darklegend1380@gmail.com` with:
  - Description of the bypass
  - Reproduction command or tool payload
  - Impact assessment

### Expected Timeline
- **Acknowledgment:** Within 48 hours
- **Assessment & Triage:** Within 5 business days
- **Fix & Corpus Regression Test:** Shipped in a patch release
