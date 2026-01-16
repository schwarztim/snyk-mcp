# Data Flow Diagrams

## Overview

This document describes how data flows through the Snyk MCP Server, including trust boundaries, data transformations, and sensitive data handling.

## High-Level Data Flow

```mermaid
flowchart LR
    subgraph user_space["User Space"]
        User[User]
        AI[AI Assistant]
    end

    subgraph mcp_space["MCP Server Space"]
        MCP[Snyk MCP Server]
    end

    subgraph snyk_space["Snyk Cloud"]
        API[Snyk APIs]
        DB[(Vuln DB)]
    end

    User -->|1. Natural language query| AI
    AI -->|2. Tool invocation| MCP
    MCP -->|3. API request| API
    API -->|4. Query| DB
    DB -->|5. Data| API
    API -->|6. API response| MCP
    MCP -->|7. Formatted result| AI
    AI -->|8. Natural language response| User
```

## Data Flow by Operation Type

### Query Operations (Read)

```mermaid
sequenceDiagram
    participant User
    participant Claude as AI Assistant
    participant MCP as Snyk MCP
    participant REST as Snyk REST API
    participant V1 as Snyk V1 API

    User->>Claude: "Show me critical vulnerabilities"
    Claude->>MCP: CallTool: snyk_list_issues

    Note over MCP: Validate args, get org_id

    MCP->>REST: GET /orgs/{org}/issues?severity=critical
    REST-->>MCP: {data: [...issues]}

    Note over MCP: Transform response

    MCP-->>Claude: {count: N, issues: [...]}
    Claude-->>User: "Found N critical issues..."
```

### Mutation Operations (Write)

```mermaid
sequenceDiagram
    participant User
    participant Claude as AI Assistant
    participant MCP as Snyk MCP
    participant V1 as Snyk V1 API

    User->>Claude: "Ignore this vulnerability"
    Claude->>MCP: CallTool: snyk_ignore_issue

    Note over MCP: Validate required args

    MCP->>V1: POST /org/{org}/project/{proj}/ignore/{issue}
    V1-->>MCP: {success: true, ignore: {...}}

    MCP-->>Claude: {success: true, ignore: {...}}
    Claude-->>User: "Issue has been ignored"
```

## Trust Boundaries

```mermaid
flowchart TB
    subgraph tb1["Trust Boundary 1: User System"]
        User[User]
        Claude[Claude Desktop]
        MCP[Snyk MCP Server]
        Config[Config/Env Vars]
    end

    subgraph tb2["Trust Boundary 2: Network"]
        TLS[TLS Channel]
    end

    subgraph tb3["Trust Boundary 3: Snyk Cloud"]
        API[Snyk API Gateway]
        Auth[Auth Service]
        Core[Core Services]
        DB[(Database)]
    end

    User --> Claude
    Claude --> MCP
    Config -.-> MCP
    MCP --> TLS
    TLS --> API
    API --> Auth
    Auth --> Core
    Core --> DB

    style tb1 fill:#e1f5fe
    style tb2 fill:#fff3e0
    style tb3 fill:#e8f5e9
```

### Trust Boundary Analysis

| Boundary | Trust Level | Data Crossing | Controls |
|----------|-------------|---------------|----------|
| User <-> AI | High | Natural language | User authentication to Claude |
| AI <-> MCP | High | Tool calls, results | Process isolation |
| MCP <-> Network | Medium | API requests | TLS encryption |
| Network <-> Snyk | High | Authenticated requests | Token validation |

## Sensitive Data Paths

### API Token Flow

```mermaid
flowchart LR
    subgraph config["Configuration"]
        env[Environment Variable<br/>SNYK_TOKEN]
    end

    subgraph runtime["Runtime"]
        process[process.env]
        client[Axios Client]
        header[Authorization Header]
    end

    subgraph network["Network"]
        tls[TLS Encrypted Channel]
    end

    subgraph snyk["Snyk"]
        gateway[API Gateway]
    end

    env -->|Startup| process
    process -->|Client creation| client
    client -->|Request| header
    header -->|HTTPS| tls
    tls -->|Decrypted| gateway

    style env fill:#ffcdd2
    style process fill:#ffcdd2
    style client fill:#ffcdd2
    style header fill:#ffcdd2
```

**Security Controls**:
- Token never logged to stdout/stderr
- Token stored only in memory at runtime
- TLS encrypts token in transit
- Token not included in error messages

### Vulnerability Data Flow

```mermaid
flowchart TB
    subgraph snyk["Snyk Platform"]
        vuln_db[(Vulnerability Database)]
        issue_data[Issue Details]
    end

    subgraph mcp["MCP Server"]
        raw[Raw API Response]
        transform[Transform/Filter]
        sanitized[Sanitized Response]
    end

    subgraph ai["AI Assistant"]
        context[Conversation Context]
        response[User Response]
    end

    vuln_db --> issue_data
    issue_data -->|API Response| raw
    raw --> transform
    transform --> sanitized
    sanitized --> context
    context --> response

    style vuln_db fill:#e8f5e9
    style issue_data fill:#e8f5e9
```

### SBOM Data Flow

```mermaid
flowchart LR
    subgraph project["Project"]
        deps[Dependencies]
    end

    subgraph snyk["Snyk"]
        scan[Scan Results]
        sbom_gen[SBOM Generator]
    end

    subgraph mcp["MCP Server"]
        request[SBOM Request]
        response[SBOM Response]
    end

    subgraph ai["AI"]
        analysis[SBOM Analysis]
    end

    deps -->|Scanned| scan
    scan --> sbom_gen
    request --> sbom_gen
    sbom_gen --> response
    response --> analysis
```

## Data Transformations

### Input Transformation

| Stage | Data Format | Example |
|-------|-------------|---------|
| User input | Natural language | "List critical bugs" |
| AI interpretation | Tool call JSON | `{tool: "snyk_list_issues", args: {severity: ["critical"]}}` |
| MCP parsing | Typed arguments | `{effective_severity_level: ["critical"]}` |
| API request | Query params | `?effective_severity_level=critical` |

### Output Transformation

| Stage | Data Format | Example |
|-------|-------------|---------|
| API response | JSON API format | `{data: [{id: "...", attributes: {...}}]}` |
| MCP transform | Simplified JSON | `{issues: [{id: "...", title: "...", severity: "..."}]}` |
| AI formatting | Natural language | "Found 3 critical issues: ..." |

### Transformation Example

**API Response** (before):
```json
{
  "data": [{
    "id": "issue-123",
    "type": "issue",
    "attributes": {
      "title": "SQL Injection",
      "effective_severity_level": "critical",
      "status": "open",
      "ignored": false,
      "problems": [...]
    }
  }]
}
```

**MCP Response** (after):
```json
{
  "count": 1,
  "issues": [{
    "id": "issue-123",
    "title": "SQL Injection",
    "severity": "critical",
    "status": "open",
    "ignored": false
  }]
}
```

## Data Retention

| Data Type | Retention in MCP | Storage Location |
|-----------|------------------|------------------|
| API Token | Process lifetime | Memory only |
| Request args | Request scope | Memory, garbage collected |
| API responses | Request scope | Memory, garbage collected |
| Error messages | Transient | stderr |

## Data Classification

| Data Type | Classification | Handling |
|-----------|---------------|----------|
| API Token | Secret | Never log, encrypt in transit |
| Organization ID | Internal | May appear in logs |
| Project names | Internal | May appear in responses |
| Vulnerability details | Confidential | Return to authorized user only |
| SBOM data | Confidential | Contains dependency inventory |
| User info (verify_token) | PII | Limited to current user |

## Pagination Data Flow

```mermaid
flowchart TB
    subgraph mcp["MCP Server"]
        handler[Tool Handler]
        paginate[fetchAllPages]
        accumulator[Result Accumulator]
    end

    subgraph api["Snyk API"]
        page1[Page 1<br/>links.next: /page2]
        page2[Page 2<br/>links.next: /page3]
        page3[Page 3<br/>links.next: null]
    end

    handler --> paginate
    paginate -->|Request 1| page1
    page1 -->|Response + next link| paginate
    paginate -->|Request 2| page2
    page2 -->|Response + next link| paginate
    paginate -->|Request 3| page3
    page3 -->|Response| paginate
    paginate --> accumulator
    accumulator --> handler
```

## Open Questions and Gaps

1. **Data Masking**: No automatic masking of sensitive fields in responses
2. **Audit Logging**: No audit trail of data access
3. **Data Encryption**: No at-rest encryption (memory only)
4. **Rate Limit Visibility**: Rate limit headers not exposed to caller
5. **Response Size Limits**: Large SBOMs could cause memory issues
6. **PII Handling**: User email from verify_token not specially handled
