## Browser Security Mechanisms Explained (For Application Security Analyst)

---

### 1. OWASP Top 10 (2021)

1. **Broken Access Control**
   - Example: A regular user accesses `/admin/delete-user/123` and successfully deletes another user.
2. **Cryptographic Failures**
   - Example: Passwords stored in plain text or weak hashing algorithms like MD5.
3. **Injection**
   - Example: SQL Injection via `login.php?user=' OR 1=1 --`.
4. **Insecure Design**
   - Example: A payment app does not limit failed login attempts, allowing brute force attacks.
5. **Security Misconfiguration**
   - Example: Open admin console on default port with no password.
6. **Vulnerable and Outdated Components**
   - Example: A web app using an outdated jQuery version with known XSS vulnerabilities.
7. **Identification and Authentication Failures**
   - Example: No session timeout after inactivity, exposing risk on public devices.
8. **Software and Data Integrity Failures**
   - Example: CI/CD pipeline runs unsigned code from untrusted repositories.
9. **Security Logging and Monitoring Failures**
   - Example: No logging of failed login attempts or alerting on suspicious access patterns.
10. **Server-Side Request Forgery (SSRF)**

- Example: Image upload feature allows URLs like `http://localhost:8000/admin`, leaking internal data.

---

### 2. OWASP ASVS & Testing Guide

**ASVS Categories**: OWASP ASVS includes 14 verification domains:

1. Architecture, Design and Threat Modeling
2. Authentication
3. Session Management
4. Access Control
5. Validation, Sanitization and Encoding
6. Stored Cryptography
7. Error Handling and Logging
8. Data Protection
9. Communications
10. Malicious Code
11. Business Logic
12. File and Resources
13. API and Web Services
14. Configuration

**ASVS** (Application Security Verification Standard): A detailed framework from OWASP that defines a set of security requirements for designing, developing, and testing secure applications. It provides three levels of verification:

- **Level 1 (L1)**: Basic security for all applications.
- **Level 2 (L2)**: Enhanced security for applications processing sensitive data.
- **Level 3 (L3)**: Advanced security for critical systems requiring the highest assurance. ASVS covers areas such as authentication, access control, cryptography, input validation, and error handling, making it ideal for integrating security into the software development lifecycle (SDLC).
- Use during design, development, and testing.

**OWASP Testing Guide**: Step-by-step manual for security testing (e.g., SQLi, XSS, auth bypass).

- Used for manual testing, pentesting, and validating controls.

---

### 3. RBAC (Role-Based Access Control)

**Definition**: Access control model where permissions are assigned to roles, and users are assigned to those roles.

**Example**:

| Role    | Permissions                  |
| ------- | ---------------------------- |
| Admin   | Create, Read, Update, Delete |
| Analyst | Read                         |

**Test Cases**:

- Vertical Escalation: User accesses admin resources.
- Horizontal Escalation: User accesses other users' data.

Use ASVS V5 and V2 for RBAC testing.

---

### 4. Same-Origin Policy (SOP)

**Visual Aid**:

| Origin Example                                          | Considered Same Origin? |
| ------------------------------------------------------- | ----------------------- |
| `https://example.com:443` vs `https://example.com:443`  | ✅ Yes                   |
| `https://example.com` vs `http://example.com`           | ❌ No (protocol)         |
| `https://example.com` vs `https://sub.example.com`      | ❌ No (subdomain)        |
| `https://example.com:443` vs `https://example.com:8443` | ❌ No (port)             |

**Definition**: A core browser security mechanism that restricts how documents/scripts from one origin can interact with resources from another origin.

- **Origin** = Protocol + Host + Port
- **Purpose**: Prevents malicious scripts from one site accessing sensitive data from another.
- **Example**: `https://example.com` **cannot access** `http://example.com` or `https://other.com`

**Protocols under SOP enforcement**:

| Protocol | SOP-Enforced?                  |
| -------- | ------------------------------ |
| http     | ✅ Yes                          |
| https    | ✅ Yes (different from http)    |
| file     | ⚠️ Partial (browser-dependent) |
| ftp      | ⚠️ Mostly deprecated           |
| data     | ⚠️ Unique origin               |
| ws/wss   | ✅ Yes (inherits origin)        |

---

### 5. Cookies

**Definition**: Small pieces of data stored by the browser and sent with every HTTP request to the same origin.

**Main Purposes**:

- Session management (e.g., login state)
- Personalization (e.g., language preference)
- Tracking (e.g., analytics)

**Important Attributes**:

- `Secure`: Only sent over HTTPS.
- `HttpOnly`: Not accessible via JavaScript (helps prevent XSS).
- `SameSite`: Controls cross-site cookie behavior.
  - `Strict`: Sent only to same-site.
  - `Lax`: Sent with top-level GET requests.
  - `None`: Sent cross-site only if `Secure` is set.

**Security Concerns**:

- Without `HttpOnly`, vulnerable to XSS.
- Without `SameSite`, vulnerable to CSRF.

---

### 6. Content Security Policy (CSP)

**Definition**: HTTP header that restricts sources of content (scripts, styles, images, etc.).

**Purpose**:

- Mitigates XSS by disallowing inline scripts and unauthorized domains.

**Example**:

```http
Content-Security-Policy: default-src 'self'; script-src 'self' cdn.example.com;
```

---

### 7. HTTP Strict Transport Security (HSTS)

**Definition**: HTTP response header that forces browsers to use HTTPS connections.

**Purpose**: Prevents SSL stripping attacks.

**Example**:

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

---

### 8. Cross-Origin Resource Sharing (CORS)

**Definition**: Mechanism to relax SOP and allow controlled cross-origin requests.

**Headers**:

- `Access-Control-Allow-Origin`
- `Access-Control-Allow-Credentials`
- `Access-Control-Allow-Methods`

**Purpose**: Allows safe cross-origin interaction.

---

### 9. APIs (Application Programming Interfaces)

**Definition**: APIs are a set of rules and protocols that allow different software systems to communicate with each other. In web applications, they typically expose services over HTTP or HTTPS.

**Common API Types**:

- **REST**: Resource-based, stateless, uses HTTP methods.
- **GraphQL**: Query-based, allows clients to specify exact data needs.
- **SOAP**: Protocol-based, used in enterprise services.

**Common Usage in Web Apps**:

- Frontend apps fetch user data from backend APIs.
- Mobile apps authenticate users via API calls.
- External partners use exposed APIs for integration.

**Security Considerations**:

- Implement **Authentication and Authorization** (e.g., OAuth2, JWT).
- Validate input to prevent **Injection attacks**.
- Use **Rate limiting** to prevent abuse.
- Apply **CORS** rules to control access.
- Ensure **HTTPS** for all communications.

**Example Threats**:

- **Broken Object Level Authorization (BOLA)**: A user can access `/api/users/123` instead of their own ID.
- **Mass Assignment**: API accepts and applies user-supplied fields like `isAdmin=true`.

---

### 10. Threat Modeling

**Example (STRIDE)**: For a login module:

- **Spoofing**: User pretends to be another by injecting token
- **Tampering**: Modify JWT token payload to escalate privileges
- **Repudiation**: No logs exist to track failed login
- **Information Disclosure**: Verbose error message reveals valid usernames
- **Denial of Service**: Brute force attack on login form
- **Elevation of Privilege**: Bypassing RBAC to access admin panel

**Definition**: The process of identifying potential security threats, vulnerabilities, and countermeasures during the design phase of a system or feature.

**Common Models**:

- **STRIDE**: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
- **DREAD**: Damage, Reproducibility, Exploitability, Affected users, Discoverability

**Tools**:

- OWASP Threat Dragon
- Microsoft Threat Modeling Tool

**Usage**:

- Apply early in the SDLC.
- Conduct in design reviews or sprint planning.

---

### 11. Manual vs Automated Testing

**Manual Testing**:

- Done by analysts using tools like Burp Suite, Postman, or browser DevTools.
- Best for logic flaws, RBAC issues, and business logic abuse.

**Automated Testing**:

- Performed with scanners like OWASP ZAP, Nikto, Acunetix.
- Detects known vulnerabilities (e.g., missing headers, outdated components).

**Recommendation**: Combine both approaches for full coverage.

---

### 12. Penetration Testing Techniques

**Typical Steps**:

- Information Gathering (e.g., dirb, sublist3r)
- Authentication Testing (e.g., brute force, token replay)
- Authorization Testing (e.g., IDOR, privilege escalation)
- Input Validation (e.g., XSS, SQLi)

**Tools**:

- Burp Suite Pro/Community
- OWASP ZAP
- Postman for API testing

**Goal**: Simulate real attacks to discover exploitable flaws.

---

### 13. Scripting for Security Automation

**Why it matters**:

- Reduces manual effort and scales testing
- Useful for CI pipelines and red teaming

**Examples**:

- Python scripts to test JWT tokens
- Bash + curl to scan multiple endpoints
- PowerShell for Windows-based script automation

**Use Cases**:

- Mass scanning, auto-fuzzing, or API abuse testing

---

### 14. Cloud and CI/CD Security Awareness

**CI/CD with GitHub Actions**:

- GitHub Actions allows automated security scanning and deployment workflows.
- Best practices:
  - Use **secrets** stored in GitHub Secrets.
  - Run **security linters** and **code quality tools** (e.g., ESLint, Bandit, Trivy).
  - Integrate tools like **OWASP ZAP**, **Snyk**, or **Semgrep** into your pipeline.
  - Apply **least privilege** to workflow tokens (`permissions:` block).
  - Set up **branch protection rules** to prevent merging unreviewed or failed checks.

**Cloud Considerations**: **Cloud Considerations**:

- Secure secrets in AWS Secrets Manager or Azure Key Vault
- Set IAM policies with least privilege

**CI/CD Best Practices**:

- Scan code and dependencies (e.g., Snyk, Trivy)
- Use signed commits and validated pipelines
- Avoid hardcoding credentials or access tokens

**Tools**:

- Jenkins, GitLab CI/CD, Azure DevOps

---

### 15. Logging, Monitoring, and Runtime Protection

**Example Log Entry**:

```
[WARNING] Failed login attempt for user admin from IP 192.168.1.101 at 2025-07-13T10:45:23Z
```

**Alerting Rule**:

- If 3 failed login attempts occur within 5 minutes → trigger Wazuh alert or Slack notification

**Best Practices**:

- Log failed logins, privilege changes, unusual access patterns
- Use log rotation and storage protection

**Runtime Protections**:

- Security headers (CSP, HSTS, etc.)
- Basic WAF rules
- Intrusion detection (e.g., Fail2Ban, Wazuh)

**Tools**:

- ELK Stack (Elasticsearch, Logstash, Kibana)
- Wazuh
- Grafana Loki

---

### 16. International Standards and Regulations Awareness

**Why It Matters**: Application Security Analysts should understand and support compliance with international regulations and security frameworks.

**Key Frameworks**:

- **ISO/IEC 27001**: Information Security Management System (ISMS) standard. Encourages risk management, security policies, and continuous improvement.
- **GDPR** (General Data Protection Regulation): Protects personal data and privacy within the EU. Requires secure data storage, encryption, and breach notification.
- **NIS2** (Network and Information Security Directive): Enhances cybersecurity across EU critical infrastructure, especially in sectors like telecom, health, and finance.
- **DORA** (Digital Operational Resilience Act): Specific to financial services. Requires firms to maintain robust cybersecurity and incident response capabilities.

**Application in Practice**:

- Design features with privacy by design (GDPR).
- Use audit logs and reporting (ISO 27001, NIS2).
- Build incident response into DevSecOps workflows (DORA).

---

### 17. Other Security Headers

- `X-Frame-Options`: Prevents clickjacking (e.g., `DENY`, `SAMEORIGIN`).
- `Referrer-Policy`: Controls `Referer` header sent with requests.
- `Permissions-Policy`: Restricts access to browser features (e.g., geolocation).

---

