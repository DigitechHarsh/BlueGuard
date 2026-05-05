# 5. Agile Documentation

## 5.1 Agile Project Charter

| General Project Information | |
| :--- | :--- |
| **Project Title** | BlueGuard SOC Platform |
| **Project Developer** | [Your Name/Team Names Here] |
| **Project Start Date** | 01 January, 2026 |
| **Project Completion Date** | 26 April, 2026 |
| **Vision** | To build a highly intelligent, context-aware Security Operations Center (SOC) dashboard that automatically filters false positives by analyzing threats against organizational infrastructure using Gen LLM. |
| **Objective** | To integrate Wazuh SIEM, MongoDB, and Gen LLM into a unified Flask application for real-time risk assessment and threat visualization. |
| **Estimated Project Size** | Medium-sized application focused on rapid data ingestion, AI processing, and real-time frontend rendering. |
| **Key Stake Holders** | SOC Analysts, Security Managers, Project Guide. |
| **Methodology Used** | Agile (Scrum) |
| **Technologies Used** | Python, Flask, MongoDB, Tailwind CSS, JavaScript, Gen LLM API. |
| **Development Approach** | The project followed an iterative Agile approach. Sprints were divided into UI design, Webhook integration, AI engine development, and system optimization. |

---

## 5.2 Agile Roadmap

| Phase | Details |
| :--- | :--- |
| **Phase 1: Foundation (Jan 2026)** | Requirement gathering. Finalized tech stack (Python, Flask, MongoDB). Learned basic routing and NoSQL database structures. Designed system architecture and diagrams. |
| **Phase 2: UI & Ingestion (Feb 2026)** | Developed frontend templates using HTML and Tailwind CSS. Created the Flask `/webhook` route to successfully receive and parse raw JSON alerts from Wazuh. |
| **Phase 3: AI Integration (Mar 2026)** | Developed `analyzer.py`. Integrated Gen LLM API. Engineered the core prompt to inject organizational security controls (Palo Alto firewall, internal isolation). Built the Python fallback logic. |
| **Phase 4: Optimization (Apr 2026)** | Removed legacy authentication to create a streamlined, open-access internal dashboard. Implemented CSV export functionality. Final testing and documentation. |

---

## 5.3 Agile Project Plan (Sprints)

| Task Name | Responsible | Start | End | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Sprint 1: Core Setup** | Team | 01/Jan/2026 | 15/Jan/2026 | Complete |
| Setup Flask environment & Routing | Team | 01/01/2026 | 05/01/2026 | Complete |
| Install and Configure local MongoDB | Team | 06/01/2026 | 10/01/2026 | Complete |
| Connect Flask to MongoDB (PyMongo) | Team | 11/01/2026 | 15/01/2026 | Complete |
| **Sprint 2: Frontend UI** | Team | 16/Jan/2026 | 30/Jan/2026 | Complete |
| Design Dashboard Layout (Tailwind) | Team | 16/01/2026 | 22/01/2026 | Complete |
| Design Logs & Detailed View HTML | Team | 23/01/2026 | 30/01/2026 | Complete |
| **Sprint 3: Webhook & Parsing** | Team | 01/Feb/2026 | 15/Feb/2026 | Complete |
| Develop POST `/webhook` route | Team | 01/02/2026 | 07/02/2026 | Complete |
| Parse Wazuh JSON & Store in DB | Team | 08/02/2026 | 15/02/2026 | Complete |
| **Sprint 4: Gen LLM Engine** | Team | 16/Feb/2026 | 15/Mar/2026 | Complete |
| Setup `analyzer.py` and API Keys | Team | 16/02/2026 | 20/02/2026 | Complete |
| Prompt Engineering (Org Context) | Team | 21/02/2026 | 28/02/2026 | Complete |
| JSON Response Parsing & Error Handling | Team | 01/03/2026 | 07/03/2026 | Complete |
| Python Fallback Logic Implementation | Team | 08/03/2026 | 15/03/2026 | Complete |
| **Sprint 5: Refinement** | Team | 16/Mar/2026 | 15/Apr/2026 | Complete |
| Dynamic UI Tags (Mitigated, Severity) | Team | 16/03/2026 | 25/03/2026 | Complete |
| Remove Auth for Streamlined Access | Team | 26/03/2026 | 05/04/2026 | Complete |
| Implement CSV Export Functionality | Team | 06/04/2026 | 15/04/2026 | Complete |

---

## 5.4 Agile User Story

| Story Title | Description | Acceptance Criteria |
| :--- | :--- | :--- |
| **Real-Time Monitoring** | As a SOC Analyst, I want to view a Live Threat Stream so I can monitor incoming Wazuh alerts without refreshing the page. | Dashboard displays latest alerts pulled from MongoDB. UI updates dynamically. |
| **Risk Downgrading** | As a SOC Analyst, I want the system to automatically downgrade false positives so I don't suffer from alert fatigue. | The UI displays "Base Risk" vs "Org Risk" side-by-side. A "Mitigated" badge appears when risk drops. |
| **Deep Threat Intelligence** | As a Security Responder, I want detailed paragraphs explaining the attack paths so I can understand the context immediately. | Gen LLM generates a 3-5 sentence specific assessment factoring in the internal network and Palo Alto firewalls. |
| **Security Reporting** | As a Security Manager, I want to export security logs to CSV so I can present the ROI of our security controls to executives. | Clicking "Export Report" downloads a properly formatted CSV file containing all Gen LLM intelligence. |

---

## 5.5 Agile Release Plan

| Sprint | Task Name | Start | End | Duration | Status | Release Date |
| :---: | :--- | :--- | :--- | :---: | :--- | :--- |
| 1 | Setup Flask environment & Routing | 01/01/2026 | 05/01/2026 | 5 | Release | 05/01/2026 |
| 1 | Install and Configure local MongoDB | 06/01/2026 | 10/01/2026 | 5 | Release | 10/01/2026 |
| 1 | Connect Flask to MongoDB (PyMongo) | 11/01/2026 | 15/01/2026 | 5 | Release | 15/01/2026 |
| 2 | Design Dashboard Layout (Tailwind) | 16/01/2026 | 22/01/2026 | 7 | Release | 22/01/2026 |
| 2 | Design Logs & Detailed View HTML | 23/01/2026 | 30/01/2026 | 8 | Release | 30/01/2026 |
| 3 | Develop POST `/webhook` route | 01/02/2026 | 07/02/2026 | 7 | Release | 07/02/2026 |
| 3 | Parse Wazuh JSON & Store in DB | 08/02/2026 | 15/02/2026 | 8 | Release | 15/02/2026 |
| 4 | Prompt Engineering (Org Context) | 16/02/2026 | 28/02/2026 | 13 | Release | 28/02/2026 |
| 4 | JSON Response Parsing & Error Handling | 01/03/2026 | 07/03/2026 | 7 | Release | 07/03/2026 |
| 4 | Python Fallback Logic Implementation | 08/03/2026 | 15/03/2026 | 8 | Release | 15/03/2026 |
| 5 | Dynamic UI Tags (Mitigated, Severity) | 16/03/2026 | 25/03/2026 | 10 | Release | 25/03/2026 |
| 5 | Remove Auth for Streamlined Access | 26/03/2026 | 05/04/2026 | 11 | Release | 05/04/2026 |
| 5 | Implement CSV Export Functionality | 06/04/2026 | 15/04/2026 | 10 | Release | 15/04/2026 |

---

## 5.6 Agile Sprint Backlog

| Task ID | Task Description | Original Estimate (Hours) | Status |
| :--- | :--- | :--- | :--- |
| T-01 | Setup Flask and MongoDB connection | 8 | Completed |
| T-02 | Create HTML/Tailwind Templates | 15 | Completed |
| T-03 | Write Webhook JSON parsing logic | 10 | Completed |
| T-04 | Gen LLM Prompt Engineering | 12 | Completed |
| T-05 | Code Fallback Python Logic | 8 | Completed |
| T-06 | Implement UI Logic for "Mitigated" Tags | 6 | Completed |
| T-07 | CSV Export Script | 5 | Completed |
| T-08 | System Testing & Bug Fixing | 15 | Completed |

---

## 5.7 Agile Test Plan

| Test ID | Date | Action | Input Data | Expected Result | Actual Result | Pass/Fail |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | 05/02 | Test Webhook Ingestion | Raw Wazuh JSON payload | HTTP 200 OK, Document saved in DB | Document verified in MongoDB | **Pass** |
| 2 | 02/03 | Gen LLM Integration | Alert description string | Gen LLM returns valid structured JSON | Valid JSON parsed and stored | **Pass** |
| 3 | 10/03 | Fallback Logic Trigger | Disconnect internet / Invalid API key | System triggers hardcoded Python rules | Alert processed via Python fallback | **Pass** |
| 4 | 20/03 | UI Severity Mapping | Base Risk: High, Org Risk: Low | "Mitigated" tag appears in Blue | Tag renders correctly on Dashboard | **Pass** |
| 5 | 10/04 | CSV Export | Click Export Button | Browser downloads `.csv` file | File downloaded with all columns | **Pass** |

---

## 5.8 Earned-value and Burn Charts

Earned Value Management (EVM) and Burn Charts are essential tools used in Agile development to measure a project's performance in terms of schedule and cost efficiency. For the BlueGuard project, these metrics helped the team monitor progress across all 5 sprints, ensuring timely delivery of complex AI features.

### Burn Down Chart:
*(Placeholder: Insert your Burn Down Chart image here showing the steady completion of hours across Sprint 1 to Sprint 5)*

### Burn Up Chart:
*(Placeholder: Insert your Burn Up Chart image here showing the cumulative work completed over time reaching the Total Scope line)*
