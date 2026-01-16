# Changelog

All notable changes to the Snyk MCP Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-01-16

### Added

#### New Policies API Endpoints (2025 API Features)
- **snyk_list_policies**: List all policies for an organization or group with pagination support
- **snyk_get_policy**: Get detailed information about a specific policy
- **snyk_create_policy**: Create new policies for organizations or groups with action types and conditions
- **snyk_update_policy**: Update existing policies using PATCH endpoint
- Support for both org-level and group-level policy management
- Full integration with Snyk's 2025-11-05 API version for policies

#### Enhanced Input Validation
- Added `validateRequired()` helper for required parameter validation with clear error messages
- Added `validateEnum()` helper for enum parameter validation with allowed values listing
- Improved error messages across all endpoints with actionable help text

### Performance Improvements

#### HTTP Connection Pooling
- Implemented HTTP/HTTPS agent-based connection pooling with `keepAlive: true`
- Configured connection pool with 50 max sockets and 10 max free sockets for optimal performance
- Added 60-second timeout for idle connections
- Reduced TCP handshake overhead by reusing connections across multiple API calls

#### Singleton Client Pattern
- Implemented lazy singleton pattern for REST and V1 API clients
- Clients are created once and reused throughout the server lifecycle
- Eliminated redundant client instantiation overhead
- Improved memory efficiency by maintaining single client instances

#### Request Timeouts
- Added 30-second timeout for all HTTP requests to prevent hanging requests
- Provides better error handling for slow or unresponsive API endpoints

### Performance Impact
- **Connection Reuse**: HTTP connection pooling reduces latency by ~50-100ms per request after initial connection
- **Memory Efficiency**: Singleton pattern reduces memory allocation overhead
- **Reliability**: Request timeouts prevent indefinite waiting on slow endpoints

### Security
- No vulnerabilities found in dependencies (verified with npm audit)
- All credentials properly validated before API calls
- No hardcoded secrets or tokens in source code

### Changed
- Updated default API version to support latest Snyk REST API features
- Enhanced error formatting to include more context and remediation suggestions

## [1.0.0] - Initial Release

### Added
- Initial implementation of Snyk MCP Server
- Support for 18 core Snyk API endpoints
- Organization and project management
- Issue and vulnerability tracking
- SBOM export functionality
- Package testing capabilities
- Dependency analysis
- Project activation/deactivation
- Issue ignore/unignore functionality
