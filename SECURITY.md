# SECURITY.md — patchpilot
# Customer: AITurn (internal)

Generated from `~/hermes-admin/security-framework.md` template.

## Data Classification

| Data type | Classification | Retention | Encryption |
|-----------|---------------|-----------|------------|
| [e.g., Customer PII] | [Restricted/Confidential/Internal/Public] | [N days/permanent] | [at rest / in transit / both] |

## Threat Model

1. **Worst case:** [What's the most damaging thing that could happen?]
2. **Most likely:** [What's the most probable attack?]
3. **Mitigations:** [What we did to prevent both]

## Secrets

| Secret | Stored in | Scope | Rotation |
|--------|----------|-------|----------|
| [e.g., Stripe API key] | `.env` (600 perms) | [read-only / write / admin] | [90 days] |

## Security Tier: High

### Tier-specific requirements applied:

{{#if TIER == "Critical"}}
- [ ] Docker container isolation (mandatory)
- [ ] Full OWASP LLM Top 10 review
- [ ] Second-agent code review on all changes
- [ ] Penetration test before deploy
- [ ] PCI-DSS controls (if payments)
- [ ] Quarterly security re-review
- [ ] Authentication audit (OWASP ASVS Level 2)
{{/if}}

{{#if TIER == "High"}}
- [ ] Docker recommended
- [ ] Core security checklists
- [ ] Dependency CVE audit
- [ ] Least-privilege review
- [ ] Agent instructions reviewed for injection
{{/if}}

{{#if TIER == "Standard"}}
- [ ] Secrets scan
- [ ] Basic input validation
- [ ] .gitignore check
{{/if}}

## Audit Trail

| Date | Activity | Result | By |
|------|----------|--------|-----|
| [date] | Initial security assessment | [result] | Hermes |
| | | | |

## Incident Response

- **Primary contact:** [owner contact method]
- **Containment steps:** 
  1. [First action to stop the breach]
  2. [Second action]
- **Recovery steps:**
  1. [How to restore service]
  2. [How to verify integrity]
