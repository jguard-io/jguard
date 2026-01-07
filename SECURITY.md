# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

The jGuard team takes security vulnerabilities seriously. We appreciate your
efforts to responsibly disclose your findings.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them using one of these methods:

1. **GitHub Private Vulnerability Reporting** (Preferred)

   Use GitHub's private vulnerability reporting feature:
   [Report a vulnerability](https://github.com/jguard-io/jguard/security/advisories/new)

2. **Email**

   Send an email to **security@lucenia.io** with:
   - A description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact assessment
   - Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within 48 hours.
- **Initial Assessment**: Within 7 days, we will provide an initial assessment
  and expected timeline for a fix.
- **Updates**: We will keep you informed of our progress toward resolving the
  issue.
- **Disclosure**: We will coordinate with you on the timing of public disclosure.

### Safe Harbor

We consider security research conducted in accordance with this policy to be:

- Authorized under the Computer Fraud and Abuse Act (CFAA)
- Exempt from DMCA restrictions on circumvention
- Lawful and conducted in good faith

We will not pursue legal action against researchers who:

- Act in good faith
- Avoid privacy violations and data destruction
- Do not exploit vulnerabilities beyond what is necessary to demonstrate them
- Report vulnerabilities promptly

### Scope

The following are in scope for security research:

- jGuard core framework
- jGuard agent
- Policy compiler and validator
- Gradle plugin

Out of scope:

- Third-party dependencies (report to upstream maintainers)
- Social engineering attacks
- Denial of service attacks

## Security Best Practices for jGuard Users

When using jGuard in production:

1. **Principle of Least Privilege**: Grant only the capabilities each module
   actually needs.

2. **Review Policies**: Audit your `module-info.jguard` files regularly.

3. **Use Strict Mode**: Run with `-Djguard.mode=strict` in production.

4. **Keep Updated**: Stay current with jGuard releases for security fixes.

5. **External Policies**: Use external policy files in production so you can
   update entitlements without redeploying:
   ```bash
   java -javaagent:jguard-agent.jar=/etc/myapp/policy.bin -jar myapp.jar
   ```

## Acknowledgments

We gratefully acknowledge security researchers who help improve jGuard.
Contributors who report valid security issues will be recognized here
(with permission).
