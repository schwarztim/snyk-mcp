# Component Diagram - C4 Level 3

## Overview

This document details the internal structure of the Snyk MCP Server, showing the key components, their responsibilities, and interactions within the Node.js process.

## Component Diagram

```mermaid
C4Component
    title Component Diagram - Snyk MCP Server

    Container_Boundary(mcp_server, "Snyk MCP Server Process") {
        Component(server, "MCP Server", "Server class", "Handles MCP protocol, routes requests")
        Component(transport, "Stdio Transport", "StdioServerTransport", "stdin/stdout communication")
        Component(tool_registry, "Tool Registry", "Tool[]", "Tool definitions with schemas")
        Component(tool_handlers, "Tool Handlers", "async functions", "Business logic for each tool")
        Component(rest_client, "REST API Client", "AxiosInstance", "Snyk REST API wrapper")
        Component(v1_client, "V1 API Client", "AxiosInstance", "Snyk V1 API wrapper")
        Component(pagination, "Pagination Helper", "fetchAllPages()", "Handles paginated responses")
        Component(error_handler, "Error Handler", "formatError()", "Standardizes error responses")
    }

    System_Ext(mcp_sdk, "@modelcontextprotocol/sdk", "MCP protocol implementation")
    System_Ext(axios, "axios", "HTTP client library")
    System_Ext(snyk_rest, "Snyk REST API", "api.snyk.io/rest")
    System_Ext(snyk_v1, "Snyk V1 API", "api.snyk.io/v1")

    Rel(server, transport, "Uses")
    Rel(server, tool_registry, "Lists tools from")
    Rel(server, tool_handlers, "Dispatches to")
    Rel(tool_handlers, rest_client, "Uses")
    Rel(tool_handlers, v1_client, "Uses")
    Rel(tool_handlers, pagination, "Uses")
    Rel(tool_handlers, error_handler, "Uses")
    Rel(rest_client, snyk_rest, "HTTPS")
    Rel(v1_client, snyk_v1, "HTTPS")
    Rel(server, mcp_sdk, "Implements")
    Rel(rest_client, axios, "Based on")
    Rel(v1_client, axios, "Based on")
```

## Component Details

### MCP Server

**File**: `src/index.ts` (lines 1113-1124)

```typescript
const server = new Server(
  { name: "snyk-mcp", version: "1.0.0" },
  { capabilities: { tools: {} } }
);
```

| Responsibility | Description |
|---------------|-------------|
| Protocol handling | Implements MCP JSON-RPC protocol |
| Request routing | Maps tool names to handlers |
| Response formatting | Wraps results in MCP response format |
| Lifecycle management | Starts/stops server |

### Stdio Transport

**File**: `src/index.ts` (lines 1256-1257)

```typescript
const transport = new StdioServerTransport();
await server.connect(transport);
```

| Responsibility | Description |
|---------------|-------------|
| Input parsing | Reads JSON-RPC from stdin |
| Output writing | Writes JSON-RPC to stdout |
| Buffering | Handles message boundaries |

### Tool Registry

**File**: `src/index.ts` (lines 186-558)

The tool registry is a static array of 17 tool definitions:

| Category | Tools |
|----------|-------|
| Auth | `snyk_verify_token` |
| Organizations | `snyk_list_orgs`, `snyk_get_org`, `snyk_get_org_entitlements` |
| Projects | `snyk_list_projects`, `snyk_get_project`, `snyk_activate_project`, `snyk_deactivate_project` |
| Issues | `snyk_list_issues`, `snyk_get_issue`, `snyk_get_project_aggregated_issues`, `snyk_ignore_issue` |
| Dependencies | `snyk_list_dependencies`, `snyk_test_package`, `snyk_list_package_issues` |
| SBOM | `snyk_get_sbom` |
| Targets | `snyk_list_targets` |

Each tool definition includes:
- `name`: Unique tool identifier
- `description`: Natural language description
- `inputSchema`: JSON Schema for arguments

### Tool Handlers

**File**: `src/index.ts` (lines 561-1110)

Each tool has a dedicated async handler function:

```typescript
async function handleListProjects(args: {...}): Promise<string>
async function handleGetIssue(args: {...}): Promise<string>
// ... etc
```

| Pattern | Description |
|---------|-------------|
| Input validation | Check required args, use defaults |
| Client selection | Choose REST or V1 API |
| API call | Make HTTP request |
| Response transformation | Map API response to simplified JSON |
| Error handling | Catch and format errors |

### REST API Client Factory

**File**: `src/index.ts` (lines 104-119)

```typescript
function createRestClient(): AxiosInstance {
  return axios.create({
    baseURL: "https://api.snyk.io/rest",
    headers: {
      "Authorization": `token ${SNYK_TOKEN}`,
      "Content-Type": "application/vnd.api+json",
    },
    params: { version: SNYK_API_VERSION },
  });
}
```

| Configuration | Value |
|--------------|-------|
| Base URL | `https://api.snyk.io/rest` |
| Auth | Token in Authorization header |
| Content-Type | `application/vnd.api+json` |
| Version | Query param (default: 2024-10-15) |

### V1 API Client Factory

**File**: `src/index.ts` (lines 121-133)

```typescript
function createV1Client(): AxiosInstance {
  return axios.create({
    baseURL: "https://api.snyk.io/v1",
    headers: {
      "Authorization": `token ${SNYK_TOKEN}`,
      "Content-Type": "application/json",
    },
  });
}
```

| Configuration | Value |
|--------------|-------|
| Base URL | `https://api.snyk.io/v1` |
| Auth | Token in Authorization header |
| Content-Type | `application/json` |

### Pagination Helper

**File**: `src/index.ts` (lines 136-161)

```typescript
async function fetchAllPages<T>(
  client: AxiosInstance,
  initialUrl: string,
  maxPages: number = 10
): Promise<T[]>
```

| Feature | Description |
|---------|-------------|
| Generic | Works with any paginated resource |
| Link following | Parses `links.next` from responses |
| Page limit | Configurable max pages (default: 10) |
| Accumulation | Concatenates all page results |

### Error Handler

**File**: `src/index.ts` (lines 164-183)

```typescript
function formatError(error: unknown): string
```

| Error Type | Handling |
|-----------|----------|
| Axios error | Extract status, error details from response |
| Standard Error | Use message property |
| Unknown | Convert to string |

## Component Interactions

### Tool Invocation Flow

```mermaid
sequenceDiagram
    participant Host as MCP Host
    participant Server as MCP Server
    participant Handler as Tool Handler
    participant Client as API Client
    participant Snyk as Snyk API

    Host->>Server: CallToolRequest (stdin)
    Server->>Server: Parse request, validate
    Server->>Handler: Dispatch to handler
    Handler->>Handler: Validate arguments
    Handler->>Client: Create client instance
    Handler->>Snyk: HTTP request
    Snyk-->>Handler: API response
    Handler->>Handler: Transform response
    Handler-->>Server: JSON string result
    Server-->>Host: CallToolResponse (stdout)
```

### API Client Selection Logic

```mermaid
flowchart TD
    A[Tool Handler] --> B{Which API?}
    B -->|Organizations, Projects, Issues, Targets, SBOM, Package Issues| C[REST API Client]
    B -->|Token verify, Test package, Dependencies, Aggregated issues, Ignore, Activate/Deactivate, Entitlements| D[V1 API Client]
    C --> E[api.snyk.io/rest]
    D --> F[api.snyk.io/v1]
```

## Type System

### Key Interfaces

**File**: `src/index.ts` (lines 22-101)

```typescript
interface SnykOrg {
  id: string;
  attributes: { name: string; slug: string; ... };
}

interface SnykProject {
  id: string;
  attributes: { name: string; type: string; origin: string; ... };
}

interface SnykIssue {
  id: string;
  attributes: { title: string; severity: string; ... };
}

interface SnykTarget {
  id: string;
  attributes: { display_name: string; url?: string; ... };
}

interface PaginatedResponse<T> {
  data: T[];
  links?: { next?: string; ... };
}
```

## Code Metrics

| Metric | Value |
|--------|-------|
| Total lines | 1266 |
| Tools defined | 17 |
| Handler functions | 17 |
| Interfaces | 5 |
| Helper functions | 4 |
| Dependencies | 2 (axios, @modelcontextprotocol/sdk) |

## Open Questions and Gaps

1. **Code Organization**: All code in single file; could benefit from modular structure
2. **Type Safety**: Some `Record<string, unknown>` types could be more specific
3. **Input Validation**: Schema validation relies on caller; no runtime validation
4. **Logging**: Only stderr for startup; no structured logging
5. **Configuration**: No config file support; environment only
6. **Extensibility**: Adding tools requires modifying single file
