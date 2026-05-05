# 5.7 Agile Test Plan (Comprehensive Engineering Validation)

The following test plan outlines the rigorous verification process undertaken to ensure the reliability, security, and intelligence of the BlueGuard AI SOC Platform. The tests are categorized into Integration, Functional, AI Logic, Security, and UI/UX validation.

| Test ID | Category | Test Objective | Input / Action | Expected Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **INT-01** | Integration | Flask Server Initialization | Run app.py command | Web server starts successfully on Port 5000 | Pass |
| **INT-02** | Integration | MongoDB Handshake | Backend boot-up | PyMongo confirms active connection to local DB | Pass |
| **INT-03** | Integration | Wazuh Webhook Path | Send HTTP POST to /webhook | Request received with 200 OK status | Pass |
| **INT-04** | Integration | OpenRouter API Auth | Trigger dummy AI call | API returns valid session token | Pass |
| **FUN-01** | Functional | Webhook JSON Parsing | Valid Wazuh alert payload | System extracts 'agent_name' and 'rule_desc' correctly | Pass |
| **FUN-02** | Functional | Empty Description Handling | Alert with null description | System assigns "Undetermined Threat" as fallback | Pass |
| **FUN-03** | Functional | Large Log Storage | 50,000 character log string | Document saved in MongoDB without truncation | Pass |
| **FUN-04** | Functional | Data Persistence Check | Restart Flask server | Historical alerts remain visible on Dashboard | Pass |
| **AI-01** | AI Logic | Threat Classification | "Brute force attack" log | AI classifies attack_type as "Credential Access" | Pass |
| **AI-02** | AI Logic | MITRE Mapping | "SQL Injection" log | AI maps technique to MITRE T1190 | Pass |
| **AI-03** | AI Logic | CVE Link Generation | Vulnerability in Apache 2.4 | System generates clickable link to NVD | Pass |
| **AI-04** | AI Logic | Org-Risk Calculation | Threat on internal isolated IP | Org Risk Severity is lower than Base Severity | Pass |
| **AI-05** | AI Logic | Remediation Generation | "WannaCry Ransomware" | AI provides specific steps (Isolate, Patch SMB) | Pass |
| **AI-06** | AI Logic | Safety Override (Manual) | Log contains "Malware" | Severity is forced to HIGH regardless of AI output | Pass |
| **AI-07** | AI Logic | Fallback Risk Logic | Disconnect Internet | System uses hardcoded Python rules to assign risk | Pass |
| **UI-01** | UI/UX | Severity Color Mapping | Alert with "Critical" risk | UI row renders with high-visibility Red background | Pass |
| **UI-02** | UI/UX | Mitigated Badge Logic | Risk reduction detected | Blue downward arrow "Mitigated" badge appears | Pass |
| **UI-03** | UI/UX | Dashboard Pagination | Click "Next Page" | UI displays records 11-20 without lag | Pass |
| **UI-04** | UI/UX | Search Functionality | Filter by Agent ID | Only alerts from the specific agent are shown | Pass |
| **UI-05** | UI/UX | Responsive Layout | Open UI on 13-inch laptop | Elements resize using Tailwind grid system | Pass |
| **UI-06** | UI/UX | Detailed Modal View | Click row on Live Stream | Modal opens showing full AI forensic analysis | Pass |
| **SEC-01** | Security | Environment Protection | Access .env via browser | 404/403 Error; Secret keys remain hidden | Pass |
| **SEC-02** | Security | NoSQL Injection | Input `{"$gt": ""}` in search | System treats input as literal string; no breach | Pass |
| **SEC-03** | Security | XSS Payload Filtering | `<script>alert(1)</script>` | UI renders as plain text; no script execution | Pass |
| **SEC-04** | Security | API Rate Limiting | Send 100 alerts in 10 secs | Flask handles requests via queue (no crash) | Pass |
| **REP-01** | Reporting | CSV Export Execution | Click "Export Report" | Browser initiates download of incidents.csv | Pass |
| **REP-02** | Reporting | CSV Content Accuracy | Open CSV in Excel | All 18 AI-enriched columns are present and readable | Pass |
| **PER-01** | Performance | Webhook Latency | Single alert ingestion | End-to-end processing under 3 seconds | Pass |
| **PER-02** | Performance | Database Query Speed | 5,000 records in DB | Dashboard loads initial 10 records under 500ms | Pass |
| **PER-03** | Performance | Memory Usage | Continuous 1-hour run | Memory footprint remains stable; no leaks detected | Pass |
| **AUD-01** | Audit | Timestamp Consistency | Check DB vs UI | Timezones are consistent across all layers | Pass |
| **AUD-02** | Audit | Event Logging | Internal system error | Flask logs error to console for admin review | Pass |

---

### Test Plan Summary:
- **Total Test Cases:** 32
- **Test Execution Methodology:** Manual and Automated Scripting
- **Success Rate:** 100%
- **Tools Used:** Postman (API Testing), MongoDB Compass (Data Validation), Chrome DevTools (UI Testing).
