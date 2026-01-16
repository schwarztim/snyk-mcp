# Architecture Decision Records

## Overview

This document captures key architecture decisions made in the Snyk MCP Server, following the ADR (Architecture Decision Record) format. Each decision includes context, options considered, rationale, and consequences.

---

## ADR-001: Use Model Context Protocol (MCP)

### Status
Accepted

### Context
We need to integrate Snyk security capabilities with AI assistants. Several integration patterns exist for AI tool calling.

### Options Considered

| Option | Pros | Cons |
|--------|------|------|
| MCP | Standard protocol, stdio transport, type-safe | Newer protocol, limited ecosystem |
| OpenAI Function Calling | Widely adopted, well-documented | Vendor lock-in, HTTP required |
| LangChain Tools | Rich ecosystem, Python-native | Complex, heavy dependencies |
| Custom Integration | Full control | Maintenance burden, no standard |

### Decision
Use Model Context Protocol (MCP) via `@modelcontextprotocol/sdk`.

### Rationale
- MCP is an open standard supported by Anthropic
- stdio transport enables simple process-based integration
- Type-safe tool definitions with JSON Schema
- Growing ecosystem and community support

### Consequences
- **Positive**: Standard protocol, easy Claude Desktop integration
- **Negative**: Limited to MCP-compatible hosts
- **Risk**: Protocol may evolve, requiring updates

---

## ADR-002: Single-File Architecture

### Status
Accepted (with planned evolution)

### Context
The server needs to be simple to understand, deploy, and maintain. Code organization patterns vary from single-file to multi-module.

### Options Considered

| Option | Pros | Cons |
|--------|------|------|
| Single file | Simple, easy to navigate | Scaling challenges, testing difficulty |
| Multi-module | Better organization, testability | More complexity, build configuration |
| Monorepo packages | Maximum modularity | Overkill for current scope |

### Decision
Start with single-file architecture (`src/index.ts`).

### Rationale
- Current codebase is 1266 lines - manageable in single file
- Reduces build complexity
- Faster onboarding for contributors
- Can evolve as needs grow

### Consequences
- **Positive**: Simple mental model, fast development
- **Negative**: Harder to unit test individual components
- **Future**: Plan to refactor when crossing ~2000 lines

---

## ADR-003: Dual API Strategy (REST + V1)

### Status
Accepted

### Context
Snyk offers two API versions with different capabilities. The REST API (v2024+) is modern but incomplete; the V1 API has legacy features.

### Options Considered

| Option | Pros | Cons |
|--------|------|------|
| REST API only | Modern, consistent | Missing features (test, dependencies) |
| V1 API only | Complete features | Being deprecated |
| Dual API | Full functionality | Complexity, two auth styles |

### Decision
Use both APIs based on feature availability.

### Rationale
- REST API for: organizations, projects, issues, targets, SBOM, package issues
- V1 API for: token verification, package testing, dependencies, ignores, entitlements
- Provides comprehensive coverage with best available API for each operation

### Consequences
- **Positive**: Full feature coverage
- **Negative**: Two client configurations, potential version drift
- **Migration**: Monitor Snyk API roadmap for REST API completeness

---

## ADR-004: Environment Variable Configuration

### Status
Accepted

### Context
Configuration is needed for API tokens and default organization. Multiple configuration approaches exist.

### Options Considered

| Option | Pros | Cons |
|--------|------|------|
| Environment variables | Standard, secure, simple | No validation, flat structure |
| Config file | Structured, validated | File management, permissions |
| CLI arguments | Explicit, scriptable | Verbose, per-invocation |
| Mixed approach | Flexible | Complex precedence rules |

### Decision
Use environment variables exclusively.

### Rationale
- SNYK_TOKEN as env var keeps secrets out of files
- Claude Desktop natively supports env var injection
- Standard Node.js pattern
- Simple precedence: arg > env > default

### Consequences
- **Positive**: Secure secrets handling, simple configuration
- **Negative**: No structured config, validation at runtime only
- **Risk**: Token exposure if env exported carelessly

---

## ADR-005: Stateless Request Processing

### Status
Accepted

### Context
The server could maintain state between requests (caching, sessions) or process each request independently.

### Options Considered

| Option | Pros | Cons |
|--------|------|------|
| Stateless | Simple, reliable, scalable | No caching, repeated API calls |
| Stateful with cache | Performance, reduced API calls | Staleness, memory growth |
| Hybrid | Best of both | Complexity |

### Decision
Fully stateless design with no caching.

### Rationale
- Snyk data changes frequently (new scans, new vulnerabilities)
- Caching introduces staleness risks
- Simplifies error handling and recovery
- Memory footprint remains constant

### Consequences
- **Positive**: Always fresh data, simple code, predictable memory
- **Negative**: Higher API call volume, latency on repeated queries
- **Mitigation**: Consider response caching for immutable data (e.g., historical issues)

---

## ADR-006: Axios for HTTP Client

### Status
Accepted

### Context
An HTTP client is needed for Snyk API communication. Node.js offers multiple options.

### Options Considered

| Option | Pros | Cons |
|--------|------|------|
| Axios | Popular, interceptors, transforms | Bundle size |
| node-fetch | Lightweight, standard API | Less features |
| Got | Modern, retries built-in | Less common |
| Native https | No dependencies | Low-level, verbose |

### Decision
Use Axios for HTTP client.

### Rationale
- Well-documented and widely used
- Built-in request/response interceptors
- Easy base URL and default header configuration
- TypeScript support
- Instance creation for different API bases

### Consequences
- **Positive**: Developer familiarity, good DX
- **Negative**: Additional dependency
- **Technical**: Good TypeScript integration

---

## ADR-007: JSON Schema for Tool Definitions

### Status
Accepted

### Context
MCP tools require input schema definitions. Several schema formats are available.

### Options Considered

| Option | Pros | Cons |
|--------|------|------|
| JSON Schema | MCP native, well-supported | Verbose |
| TypeScript types | Type-safe, DRY | Not directly usable by MCP |
| Zod | Validation + types | Additional dependency |

### Decision
Use JSON Schema directly in tool definitions.

### Rationale
- MCP protocol uses JSON Schema natively
- No additional dependencies
- Schema visible in tool listings
- AI assistant can use schema for argument validation

### Consequences
- **Positive**: Standard format, no translation needed
- **Negative**: Schema duplication with TypeScript types
- **Improvement**: Consider zod-to-json-schema for DRY approach

---

## ADR-008: Error Response Format

### Status
Accepted

### Context
Errors need to be communicated back to the AI assistant in a usable format.

### Options Considered

| Option | Pros | Cons |
|--------|------|------|
| Throw exceptions | Standard pattern | MCP catches, loses context |
| JSON error object | Structured, parseable | Manual handling |
| String message | Simple | Limited structure |
| Standard error format | Consistent | More implementation |

### Decision
Return JSON string with error property for failures.

### Rationale
```typescript
return JSON.stringify({ error: formatError(error) }, null, 2);
```
- Consistent with success responses (JSON)
- AI can parse and understand error context
- Includes HTTP status when available

### Consequences
- **Positive**: Consistent format, actionable error messages
- **Negative**: Error responses mixed with success responses
- **Improvement**: Consider separate error schema

---

## ADR-009: Pagination Strategy

### Status
Accepted

### Context
Snyk APIs return paginated results. A strategy is needed for handling pagination.

### Options Considered

| Option | Pros | Cons |
|--------|------|------|
| Single page only | Simple | Incomplete results |
| Follow all pages | Complete results | Slow, memory intensive |
| Configurable limit | Flexible | Complexity |
| Streaming | Memory efficient | MCP doesn't support streaming |

### Decision
Implement `fetchAllPages` with configurable max pages (default: 10).

### Rationale
- Most queries won't exceed 1000 items (10 pages x 100)
- Prevents runaway pagination
- Generic implementation for all paginated endpoints
- Caller can adjust limit via tool arguments

### Consequences
- **Positive**: Complete results for typical use cases
- **Negative**: May truncate very large result sets
- **Improvement**: Add warning when max pages reached

---

## ADR-010: TypeScript Strict Mode

### Status
Accepted

### Context
TypeScript offers various strictness levels affecting type safety.

### Options Considered

| Option | Pros | Cons |
|--------|------|------|
| Strict mode | Maximum type safety | More verbose, stricter |
| Loose mode | Faster development | More runtime errors |
| Custom config | Balanced | Inconsistent |

### Decision
Enable `"strict": true` in tsconfig.json.

### Rationale
- Catches type errors at compile time
- Forces explicit type annotations
- Prevents null/undefined errors
- Industry best practice

### Consequences
- **Positive**: Fewer runtime errors, better code quality
- **Negative**: More verbose type annotations
- **Technical**: Some `as` casts needed for dynamic API responses

---

## ADR-011: stdio Transport

### Status
Accepted

### Context
MCP supports multiple transports: stdio, HTTP, WebSocket.

### Options Considered

| Option | Pros | Cons |
|--------|------|------|
| stdio | Simple, secure, no networking | Single client |
| HTTP | Multi-client, standard | Auth complexity, exposure |
| WebSocket | Real-time, bidirectional | Connection management |

### Decision
Use stdio transport via `StdioServerTransport`.

### Rationale
- Simplest transport option
- Process isolation provides security
- Claude Desktop expects stdio
- No network port management

### Consequences
- **Positive**: Secure, simple, no network exposure
- **Negative**: Single client per process
- **Future**: HTTP transport could be added for multi-client scenarios

---

## ADR-012: Minimal Logging

### Status
Accepted (with planned improvement)

### Context
Logging is needed for debugging and monitoring. Logging verbosity and destination need definition.

### Options Considered

| Option | Pros | Cons |
|--------|------|------|
| No logging | Simple | Hard to debug |
| stderr only | Doesn't interfere with MCP | Not structured |
| Structured logging | Searchable, parseable | More code |
| External logger | Feature-rich | Dependency |

### Decision
Log only to stderr, minimal messages.

### Rationale
- stdout reserved for MCP protocol
- stderr appropriate for diagnostic messages
- Startup message confirms server is running
- Errors already in response JSON

### Consequences
- **Positive**: Simple, doesn't interfere with MCP
- **Negative**: Limited observability
- **Improvement**: Add structured JSON logging with levels

---

## Decision Log Summary

| ADR | Decision | Status | Impact |
|-----|----------|--------|--------|
| 001 | Use MCP | Accepted | High |
| 002 | Single-file architecture | Accepted | Medium |
| 003 | Dual API strategy | Accepted | Medium |
| 004 | Environment variable config | Accepted | Low |
| 005 | Stateless processing | Accepted | Medium |
| 006 | Axios HTTP client | Accepted | Low |
| 007 | JSON Schema for tools | Accepted | Low |
| 008 | JSON error format | Accepted | Low |
| 009 | Pagination with limits | Accepted | Medium |
| 010 | TypeScript strict mode | Accepted | Low |
| 011 | stdio transport | Accepted | High |
| 012 | Minimal logging | Accepted | Low |

## Open Questions and Gaps

1. **Caching Strategy**: When/if to add caching for read operations
2. **Multi-tenant**: Supporting multiple Snyk organizations simultaneously
3. **HTTP Transport**: Adding HTTP server mode for different use cases
4. **Plugin Architecture**: Making the tool system extensible
5. **Testing Strategy**: Unit vs integration test balance
6. **Versioning**: API version management strategy
