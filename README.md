# Snyk MCP Server

A Model Context Protocol (MCP) server for Snyk - Software Composition Analysis and Container Security.

## Features

This MCP server provides comprehensive access to Snyk's security platform:

### Organization Management
- `snyk_list_orgs` - List all accessible organizations
- `snyk_get_org` - Get details about a specific organization
- `snyk_get_org_entitlements` - Get feature entitlements for an organization

### Project Management
- `snyk_list_projects` - List projects with filtering (by origin, type, target)
- `snyk_get_project` - Get detailed project information
- `snyk_activate_project` - Activate a deactivated project
- `snyk_deactivate_project` - Deactivate a project to pause monitoring

### Vulnerability & Issue Management
- `snyk_list_issues` - List all issues with filtering (severity, type, ignored status)
- `snyk_get_issue` - Get detailed issue information
- `snyk_get_project_aggregated_issues` - Get aggregated vulnerability details for a project
- `snyk_ignore_issue` - Ignore an issue with reason and optional expiration

### Dependency Analysis
- `snyk_list_dependencies` - List all dependencies for a project
- `snyk_test_package` - Test a package for vulnerabilities (npm, maven, pip, etc.)
- `snyk_list_package_issues` - List vulnerabilities for a package using PURL

### SBOM & Targets
- `snyk_get_sbom` - Export SBOM in CycloneDX or SPDX format
- `snyk_list_targets` - List targets (repositories, registries) in an organization

### Authentication
- `snyk_verify_token` - Verify API token and get user information

## Installation

```bash
npm install
npm run build
```

## Configuration

Set the following environment variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `SNYK_TOKEN` | Yes | Your Snyk API token |
| `SNYK_ORG_ID` | No | Default organization ID (can be overridden per-call) |
| `SNYK_API_VERSION` | No | API version (default: 2024-10-15) |

### Getting your Snyk API Token

1. Log in to [Snyk](https://app.snyk.io)
2. Go to Account Settings
3. Under "General", find "Auth Token"
4. Click "Generate" to create a new token

### Finding your Organization ID

1. In Snyk, go to Settings
2. Under "Organization", you'll see the Organization ID
3. Or use the `snyk_list_orgs` tool to list all your organizations

## Usage with Claude Desktop

Add to your Claude configuration (`~/.claude/.claude.json`):

```json
{
  "mcpServers": {
    "snyk": {
      "command": "node",
      "args": ["/path/to/snyk-mcp/dist/index.js"],
      "env": {
        "SNYK_TOKEN": "your-snyk-api-token",
        "SNYK_ORG_ID": "your-default-org-id"
      }
    }
  }
}
```

## Example Tool Usage

### List all projects in an organization
```json
{
  "tool": "snyk_list_projects",
  "arguments": {
    "origin": "github"
  }
}
```

### Test a package for vulnerabilities
```json
{
  "tool": "snyk_test_package",
  "arguments": {
    "package_manager": "npm",
    "package_name": "lodash",
    "package_version": "4.17.20"
  }
}
```

### Get issues for a specific severity
```json
{
  "tool": "snyk_list_issues",
  "arguments": {
    "effective_severity_level": ["critical", "high"],
    "ignored": false
  }
}
```

### Export SBOM
```json
{
  "tool": "snyk_get_sbom",
  "arguments": {
    "project_id": "your-project-id",
    "format": "cyclonedx+json"
  }
}
```

## API Rate Limits

- REST API: 1620 requests per minute per API key
- Issues API: 180 requests per minute per user
- V1 API: 2000 requests per minute (with some endpoint-specific limits)

## License

MIT
