# Security Policy for mcp-postgres

This document describes the security policy and vulnerability reporting process for the mcp-postgres project.

## Supported Versions
- Only the latest release is actively supported.
- Security fixes may be backported at the maintainers' discretion.

## Reporting a Vulnerability
If you discover a security vulnerability, please report it by opening a GitHub Security Advisory or by contacting the maintainers directly.

- Do **not** disclose security issues publicly until they have been reviewed and patched.
- Provide as much detail as possible to help us reproduce and address the issue.

## Security Best Practices
- Do not commit secrets or credentials (e.g., `.env` files) to the repository.
- Use least-privilege database accounts for all connections.
- Keep `MCP_ALLOW_WRITE=false` unless write operations are explicitly required.
- Regularly update dependencies and apply security patches.

## Disclosure Policy
- We will acknowledge receipt of your report within 3 business days.
- After triage, we will work to validate and patch the vulnerability as quickly as possible.
- Once a fix is available, we will publish a security advisory and credit the reporter (unless anonymity is requested).

## References
- [GitHub Security Advisories](https://docs.github.com/en/code-security/security-advisories)
- [OWASP Top Ten](https://owasp.org/www-project-top-ten/)

Thank you for helping keep mcp-postgres secure!
