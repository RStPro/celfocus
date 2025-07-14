## Application Security Analyst Interview Questions and Model Answers

---

### OWASP Top 10

**1. What types of vulnerabilities does OWASP ZAP help detect, and which OWASP categories do they map to?**
OWASP ZAP helps detect vulnerabilities such as XSS, SQL injection, security misconfigurations, and missing security headers. These map to OWASP A03 (Injection), A05 (Security Misconfiguration), and A06 (Vulnerable and Outdated Components).

**2. Can you walk through how you mitigated Broken Access Control in your CI/CD project?**
I implemented RBAC and deny-by-default policies. I also wrote Semgrep rules to detect unsafe authorization logic and tested endpoints manually using Burp Suite for IDOR and privilege escalation.

**3. How would you address Insecure Design during the feature planning phase?**
I incorporate STRIDE threat modeling early in planning, define security requirements with ASVS, and apply design principles like least privilege and fail-safe defaults.

---

### OWASP ASVS & Testing Guide

**4. How do you use ASVS to define security requirements for a new feature?**
I map feature components to ASVS categories, e.g., authentication to V2, access control to V5, and use them as checklists during design, implementation, and testing.

**5. Which ASVS verification level would you recommend for a healthcare app and why?**
Level 2 (L2), as it processes sensitive data. For highly critical apps (e.g., surgical systems), Level 3 (L3) ensures the highest assurance.

**6. How do you align manual testing procedures with the OWASP Testing Guide?**
I use OTG to plan tests per component. For example, I test authentication using OTG-AUTHN and inputs using OTG-INPVAL, aligning each with defined objectives and tools.

---

### RBAC

**7. What’s the difference between vertical and horizontal privilege escalation? How would you test for each?**
Vertical is moving from user to admin; horizontal is accessing peer data. I test by manipulating roles/tokens and modifying IDs in requests using Burp Suite.

**8. How do you validate that your access control implementation aligns with ASVS Section V5?**
I review that access is enforced on the server-side, test deny-by-default, and verify permissions are role-specific with no client-side enforcement.

---

### Browser Security

**9. Explain how Same-Origin Policy works. What conditions must match for two pages to be considered same-origin?**
The protocol, host, and port must all match. SOP prevents scripts from one origin from accessing resources from another origin.

**10. What is the function of the HttpOnly and SameSite attributes on cookies, and why are they important?**
HttpOnly prevents JS access, mitigating XSS. SameSite restricts cross-site cookie use, reducing CSRF risk.

**11. How does CSP help prevent XSS, and what’s a basic CSP policy you’ve used?**
CSP blocks inline scripts and disallows untrusted sources. Example: `Content-Security-Policy: default-src 'self'; script-src 'self'`.

**12. How would you handle a CORS misconfiguration that exposes sensitive API data?**
I would set strict `Access-Control-Allow-Origin` values, disable `Access-Control-Allow-Credentials` unless needed, and audit exposed endpoints.

---

### API Security

**13. What is BOLA and how would you detect it during API testing?**
Broken Object Level Authorization occurs when users can access objects they shouldn’t. I test this by modifying object IDs in API requests.

**14. Why is rate limiting important for API endpoints, and how would you implement it?**
It protects against brute force and abuse. Implemented using API gateways or middleware (e.g., NGINX, Express rate-limiter).

**15. Compare REST and GraphQL from a security perspective.**
REST allows tight control over exposed endpoints. GraphQL increases flexibility but also risk of over-fetching or injection if not secured. Requires strict query depth, validation, and access control.

---

### Threat Modeling

**16. Walk me through a STRIDE analysis for a login form.**
Spoofing: fake identity via token
Tampering: modify session ID
Repudiation: no logs for login failures
Information Disclosure: verbose error messages
DoS: brute-force login
EoP: bypass RBAC

**17. What tools do you use for threat modeling and how early do you integrate it into the SDLC?**
OWASP Threat Dragon and Microsoft TMT. Integrated at feature design or sprint planning.

---

### Testing

**18. What are the advantages and limitations of automated security testing tools like Bandit or Semgrep?**
Advantages: fast, repeatable, CI/CD friendly. Limitations: limited context, false positives/negatives. Complement with manual reviews.

**19. Give an example of when manual testing found a logic flaw that an automated scanner missed.**
In a user dashboard, I manually discovered that a regular user could access admin-only stats by modifying the URL — logic flaw not flagged by scanners.

---

### Pen Testing

**20. How would you test an API for IDOR vulnerabilities?**
Authenticate as User A, then change resource IDs in requests to User B’s. Check if access is incorrectly granted.

**21. Which tools do you prefer for pentesting web apps, and why?**
Burp Suite for intercept/modification, ZAP for DAST, Postman for API testing. Each fits different attack surfaces.

---

### Security Automation

**22. How have you used Python or Bash to automate security testing or scanning?**
Python scripts to iterate JWT tokens or trigger API scans; Bash to loop curl-based fuzzing across endpoints.

**23. Can you describe a script you wrote to test authentication or session management?**
I scripted login attempts with invalid tokens to test session expiration and brute-force detection. Also used Python to parse and verify JWT claims.

---

### CI/CD Security

**24. How did you use GitHub Actions to enforce secure coding practices in your pipeline?**
Integrated Bandit, Semgrep, Trivy, and ZAP in GitHub Actions. Configured Secrets, minimal permissions, and mandatory status checks on PRs.

**25. Why is it important to restrict workflow token permissions in GitHub Actions?**
To prevent privilege escalation or token misuse. Using least privilege protects secrets even if a workflow is compromised.

**26. What steps do you take to secure secrets in a CI/CD environment?**
Use GitHub Secrets, never hardcode them, restrict access, and audit usage.

---

### Logging & Monitoring

**27. How do you ensure logs are actionable and secure in production environments?**
Log important events (e.g., failed logins), redact sensitive data, store logs securely, and rotate regularly.

**28. Describe how you use Wazuh and Fail2Ban to detect intrusion attempts.**
Fail2Ban blocks brute-force IPs; Wazuh monitors logs, triggers alerts for anomalies (e.g., multiple failed logins, suspicious IPs).

---

### Compliance & Standards

**29. How do GDPR and NIS2 affect the way you build or secure an application?**
GDPR enforces data minimization, encryption, and breach notifications. NIS2 requires logging, incident handling, and risk assessments.

**30. What practices do you follow to ensure alignment with ISO/IEC 27001 in development?**
Risk-based approach, access control, secure SDLC, logging, and regular audits as part of ISMS alignment.

---

