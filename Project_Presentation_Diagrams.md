# BlueGuard - College Project Architecture Diagrams

*Tip: You can copy and paste the ````mermaid ```` code blocks into websites like [Mermaid Live Editor](https://mermaid.live) or use a VS Code Markdown preview extension to instantly render these as images for your PPT.*

---

## 1. Use Case Diagram (SOC Analyst - Restricted)
*(Yeh diagram dikhata hai ki ek regular analyst kya-kya kar sakta hai)*

```mermaid
flowchart LR
    %% Actor Node (Left Side)
    Actor(("SOC Analyst"))

    %% Main Use Cases (Central Stack)
    UC1([Login to Dashboard])
    UC2([View AI Analyzed Logs])
    UC3([View Attack Charts & Stats])
    UC4([Filter by Agent & Time])
    UC5([Export CSV Report])
    UC6([LogOut])

    %% Included Sub-Cases (Right Side Branches)
    Sub1([Authentication])
    Sub2([Fetch Data from MongoDB])
    Sub3([Generate CSV Document])

    %% Actor Connections (Solid Lines)
    Actor --- UC1
    Actor --- UC2
    Actor --- UC3
    Actor --- UC4
    Actor --- UC5
    Actor --- UC6

    %% Include Dependencies (Dotted Arrows with labels)
    UC1 -. "<<include>>" .-> Sub1
    UC2 -. "<<include>>" .-> Sub2
    UC5 -. "<<include>>" .-> Sub3
```

---

## 2. Use Case Diagram (SOC Manager - Administrative)
*(Yeh diagram dikhata hai ki Manager ke paas Agent management ki extra permissions hai)*

```mermaid
flowchart LR
    %% Actor Node (Left Side)
    Actor(("SOC Manager
    (Admin)"))

    %% Main Use Cases (Central Stack)
    UC1([Admin Login])
    UC2([View Global Dashboard])
    UC3([Register New SOC Agent])
    UC4([Get Agent Deployment Scripts])
    UC5([Analyze High-Severity Alerts])
    UC6([Export Incident Reports])
    UC7([LogOut])

    %% Included Sub-Cases (Right Side Branches)
    Sub1([Role Authentication])
    Sub2([OS Multi-Script Gen])
    Sub3([Download CSV Data])

    %% Actor Connections (Solid Lines)
    Actor --- UC1
    Actor --- UC2
    Actor --- UC3
    Actor --- UC4
    Actor --- UC5
    Actor --- UC6
    Actor --- UC7

    %% Include Dependencies (Dotted Arrows with labels)
    UC1 -. "<<include>>" .-> Sub1
    UC3 -. "<<include>>" .-> Sub2
    UC6 -. "<<include>>" .-> Sub3
```

---

## 2. Class Diagram

```mermaid
classDiagram
    class User {
        +ObjectId id
        +String username
        +String role
        +String password_hash
    }

    class Agent {
        +ObjectId id
        +String hostname
        +String ip_address
        +String os
        +Date registered_at
    }

    class Alert {
        +ObjectId id
        +Date timestamp
        +String severity
        +String attack_type
        +String remediation
        +String mitre_tactic
        +String mitre_technique
    }

    class Ticket {
        +ObjectId id
        +ObjectId alert_id
        +String sender
        +String receiver
        +String subject
        +String status
        +String priority
        +Date created_at
    }

    class BackendController {
        +login_user()
        +register_agent()
        +get_filtered_alerts()
        +create_incident_report()
        +resolve_incident()
    }

    User "1" --> "*" Alert : Views / Queries
    User "1" --> "*" Ticket : Creates (T1) / Resolves (T2)
    Alert "1" -- "1" Ticket : Linked to
    BackendController "1" --> "*" User : Authenticates
    BackendController "1" --> "*" Agent : Manages
    BackendController "1" --> "*" Alert : Fetches Data
    BackendController "1" --> "*" Ticket : Handles Workflow
```

---

## 3. Activity Diagram

```mermaid
%%{init: {'flowchart': {'nodeSpacing': 100, 'rankSpacing': 100}}}%%
flowchart TD
    %% Start
    StartNode(( )) ---|Start| Login[LOGIN]
    
    %% Authentication Loop
    Login --> Auth{Authentication}
    Auth -- "Invalid" --> Login
    
    %% Fork (Parallel Branching - Horizontal Bar)
    Auth -- "Valid" --> Fork[ ]
    style Fork fill:#000,stroke:#000,stroke-width:10px
    
    Fork --> UC1[View SOC Dashboard]
    Fork --> UC2[Analyze AI Logs & MITRE Mapping]
    Fork --> UC3[Filter by Time/Agent]
    Fork --> UC4[Manage Incident Tickets]
    Fork --> UC5[Manage Agents]
    
    %% Join (Merging Branches - Horizontal Bar)
    UC1 --> Join[ ]
    UC2 --> Join
    UC3 --> Join
    UC4 --> Join
    UC5 --> Join
    style Join fill:#000,stroke:#000,stroke-width:10px
    
    %% End Flow
    Join --> Logout[Logout]
    Logout --> EndNode((( )))
---

## 6. Database Schema Design (MongoDB Collections)
*(Yeh tables dikhate hain ki hamara database alerts aur users ka data kis format me store karta hai)*

### Table 1: Users Collection
*(User authentication aur role-based access ke liye)*

| Field Name | Data Type | Description |
| :--- | :--- | :--- |
| **_id (PK)** | ObjectId | Unique identification for each user |
| **username** | String | Unique login name of the analyst/manager |
| **password** | String | Securely hashed password string |
| **role** | String | User role (SOC Manager / SOC Analyst) |
| **created_at** | Datetime | Timestamp when the user was registered |

<br>

### Table 2: Alerts Collection
*(SIEM logs aur AI enrichment data store karne ke liye)*

| Field Name | Data Type | Description |
| :--- | :--- | :--- |
| **_id (PK)** | ObjectId | Unique identification for each alert |
| **timestamp** | Datetime | The exact time when the attack occurred |
| **severity** | String | Threat level (Critical, High, Medium, Low) |
| **attack_type** | String | AI-classified name of the attack |
| **agent_name** | String | Hostname of the compromised machine |
| **rule_desc** | String | Original description from Wazuh SIEM |
| **analysis** | String | AI-generated deep analysis of the threat |
| **remediation** | String | Steps suggested by AI to fix the issue |
| **mitre_tactic** | String | MITRE ATT&CK Tactic (e.g. Credential Access) |
| **mitre_technique** | String | MITRE Technique ID & Name (e.g. T1110) |

<br>

### Table 3: Agents Collection
*(Registered monitors aur endpoints ki details ke liye)*

| Field Name | Data Type | Description |
| :--- | :--- | :--- |
| **_id (PK)** | ObjectId | Unique identification for each agent |
| **hostname** | String | Name of the endpoint machine |
| **ip_address** | String | Network IP of the registered agent |
| **os_type** | String | Machine OS (Windows, Ubuntu, CentOS) |
| **status** | String | Current deployment status (Active/Pending) |
| **registered_at** | Datetime | Date and time of agent registration |

<br>

### Table 4: Tickets Collection
*(Incident reporting aur collaborative response workflow ke liye)*

| Field Name | Data Type | Description |
| :--- | :--- | :--- |
| **_id (PK)** | ObjectId | Unique identification for each ticket |
| **alert_id (FK)** | ObjectId | ID of the linked security alert |
| **sender** | String | Username of the Tier 1 Analyst |
| **receiver** | String | Username of the Tier 2 Responder |
| **subject** | String | Incident Title/Subject |
| **observations** | String | Detailed notes from Tier 1 analyst |
| **resolution_notes** | String | Final report from Tier 2 responder |
| **status** | String | Current state (Pending/Investigating/Resolved) |
| **priority** | String | Severity level (Critical/High/Medium/Low) |
| **created_at** | Datetime | Timestamp when the ticket was created |
```
---

## 4. Sequence Diagram 1: Automated Threat Intelligence Pipeline
*(Yeh diagram dikhata hai ki system bina user ke alert kaise process karta hai)*

```mermaid
sequenceDiagram
    autonumber
    participant SIEM as SIEM
    participant Backend as Backend
    participant AI as AI Engine
    participant DB as Database

    SIEM->>Backend: 1. Send Alert
    
    Backend->>AI: 2. Request Analysis & MITRE Mapping
    activate AI
    AI-->>Backend: 3. Return Enriched Details (MITRE + AI)
    deactivate AI
    
    Backend->>DB: 4. Save Enriched Alert
    activate DB
    DB-->>Backend: 5. Storage Confirmed
    deactivate DB
```

---

## 5. Sequence Diagram 2: Analyst Investigation & Reporting
*(Yeh diagram dikhata hai ki User dashboard se kaise interact karta hai)*

```mermaid
sequenceDiagram
    autonumber
    participant Analyst as Analyst
    participant App as App
    participant Backend as Backend
    participant DB as Database

    Analyst->>App: 1. Login
    App->>Backend: 2. Authenticate
    Backend->>DB: 3. Verify User
    DB-->>Backend: 4. User Valid
    Backend-->>App: 5. Show Dashboard
    
    Note over Analyst, DB: Incident Escalation Flow (Tier 1)
    Analyst->>App: 6. Select Alert & Click Escalate
    App->>Backend: 7. Fetch Tier 2 Responders
    Backend->>DB: 8. Query Tier 2 Users
    DB-->>Backend: 9. Return Users List
    Backend-->>App: 10. Show Escalation Form
    Analyst->>App: 11. Submit Incident Report
    App->>Backend: 12. Create Ticket Entry
    Backend->>DB: 13. Save Ticket Data
    DB-->>Analyst: 14. Ticket Assigned to Tier 2
    
    Note over Analyst, DB: Incident Resolution Flow (Tier 2)
    Analyst->>App: 15. View Assigned Missions
    App->>Backend: 16. Fetch Profile Tickets
    Backend-->>App: 17. Show Report Details
    Analyst->>App: 18. Provide Resolution Notes
    App->>Backend: 19. Update Status to Resolved
    Backend->>DB: 20. Update Ticket Record
    DB-->>Analyst: 21. Case Closed
```
