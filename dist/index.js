#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema, } from "@modelcontextprotocol/sdk/types.js";
import axios from "axios";
import { Agent as HttpAgent } from "http";
import { Agent as HttpsAgent } from "https";
// Environment variables
const SNYK_TOKEN = process.env.SNYK_TOKEN;
const SNYK_ORG_ID = process.env.SNYK_ORG_ID;
const SNYK_API_VERSION = process.env.SNYK_API_VERSION || "2024-10-15";
// Base URLs for Snyk APIs
const REST_API_BASE = "https://api.snyk.io/rest";
const V1_API_BASE = "https://api.snyk.io/v1";
// HTTP connection pooling agents for performance
const httpAgent = new HttpAgent({
    keepAlive: true,
    maxSockets: 50,
    maxFreeSockets: 10,
    timeout: 60000,
});
const httpsAgent = new HttpsAgent({
    keepAlive: true,
    maxSockets: 50,
    maxFreeSockets: 10,
    timeout: 60000,
});
// Credential check helper - returns error message if credentials missing, null if OK
function checkCredentials() {
    if (!SNYK_TOKEN) {
        return JSON.stringify({
            error: "SNYK_TOKEN environment variable is not set",
            help: "Please set the SNYK_TOKEN environment variable with your Snyk API token. " +
                "You can find your token at https://app.snyk.io/account or generate one via the Snyk CLI with 'snyk auth'.",
        }, null, 2);
    }
    return null;
}
// Input validation helper
function validateRequired(value, fieldName) {
    if (value === undefined || value === null || value === "") {
        return JSON.stringify({
            error: `Missing required parameter: ${fieldName}`,
            help: `Please provide a valid value for ${fieldName}`,
        }, null, 2);
    }
    return null;
}
function validateEnum(value, fieldName, allowedValues) {
    if (!allowedValues.includes(value)) {
        return JSON.stringify({
            error: `Invalid value for ${fieldName}: ${value}`,
            help: `Allowed values are: ${allowedValues.join(", ")}`,
            provided: value,
        }, null, 2);
    }
    return null;
}
// Singleton client instances for connection reuse (created lazily)
let restClientInstance = null;
let v1ClientInstance = null;
// Create axios instances - only call these after checking credentials
// Uses singleton pattern to reuse HTTP connections
function createRestClient() {
    if (!restClientInstance) {
        restClientInstance = axios.create({
            baseURL: REST_API_BASE,
            headers: {
                "Authorization": `token ${SNYK_TOKEN}`,
                "Content-Type": "application/vnd.api+json",
            },
            params: {
                version: SNYK_API_VERSION,
            },
            httpAgent,
            httpsAgent,
            timeout: 30000,
        });
    }
    return restClientInstance;
}
function createV1Client() {
    if (!v1ClientInstance) {
        v1ClientInstance = axios.create({
            baseURL: V1_API_BASE,
            headers: {
                "Authorization": `token ${SNYK_TOKEN}`,
                "Content-Type": "application/json",
            },
            httpAgent,
            httpsAgent,
            timeout: 30000,
        });
    }
    return v1ClientInstance;
}
// Helper to handle pagination
async function fetchAllPages(client, initialUrl, maxPages = 10) {
    const allData = [];
    let currentUrl = initialUrl;
    let pageCount = 0;
    while (currentUrl && pageCount < maxPages) {
        const response = await client.get(currentUrl);
        allData.push(...response.data.data);
        // Handle next page URL
        const nextLink = response.data.links?.next;
        if (nextLink) {
            // Next link might be relative or absolute
            currentUrl = nextLink.startsWith("http") ? nextLink.replace(REST_API_BASE, "") : nextLink;
        }
        else {
            currentUrl = undefined;
        }
        pageCount++;
    }
    return allData;
}
// Error handler
function formatError(error) {
    if (axios.isAxiosError(error)) {
        const axiosError = error;
        const status = axiosError.response?.status;
        const data = axiosError.response?.data;
        if (data?.errors && data.errors.length > 0) {
            const errorDetails = data.errors.map(e => e.detail || e.title).join("; ");
            return `Snyk API Error (${status}): ${errorDetails}`;
        }
        return `Snyk API Error (${status}): ${axiosError.message}`;
    }
    if (error instanceof Error) {
        return error.message;
    }
    return String(error);
}
// Tool definitions
const tools = [
    {
        name: "snyk_verify_token",
        description: "Verify the Snyk API token and get information about the authenticated user",
        inputSchema: {
            type: "object",
            properties: {},
            required: [],
        },
    },
    {
        name: "snyk_list_orgs",
        description: "List all organizations accessible to the authenticated user",
        inputSchema: {
            type: "object",
            properties: {
                limit: {
                    type: "number",
                    description: "Maximum number of organizations to return (default: 100)",
                },
            },
            required: [],
        },
    },
    {
        name: "snyk_get_org",
        description: "Get details about a specific organization",
        inputSchema: {
            type: "object",
            properties: {
                org_id: {
                    type: "string",
                    description: "The organization ID (uses SNYK_ORG_ID env var if not provided)",
                },
            },
            required: [],
        },
    },
    {
        name: "snyk_list_projects",
        description: "List all projects in an organization with optional filtering",
        inputSchema: {
            type: "object",
            properties: {
                org_id: {
                    type: "string",
                    description: "The organization ID (uses SNYK_ORG_ID env var if not provided)",
                },
                target_id: {
                    type: "string",
                    description: "Filter by target ID",
                },
                origin: {
                    type: "string",
                    description: "Filter by origin (e.g., github, gitlab, cli, docker-hub)",
                },
                type: {
                    type: "string",
                    description: "Filter by project type (e.g., npm, maven, pip, docker)",
                },
                limit: {
                    type: "number",
                    description: "Maximum number of projects to return (default: 100)",
                },
            },
            required: [],
        },
    },
    {
        name: "snyk_get_project",
        description: "Get details about a specific project including its configuration",
        inputSchema: {
            type: "object",
            properties: {
                org_id: {
                    type: "string",
                    description: "The organization ID (uses SNYK_ORG_ID env var if not provided)",
                },
                project_id: {
                    type: "string",
                    description: "The project ID",
                },
            },
            required: ["project_id"],
        },
    },
    {
        name: "snyk_list_issues",
        description: "List all issues (vulnerabilities) for an organization with filtering options",
        inputSchema: {
            type: "object",
            properties: {
                org_id: {
                    type: "string",
                    description: "The organization ID (uses SNYK_ORG_ID env var if not provided)",
                },
                scan_item_id: {
                    type: "string",
                    description: "Filter issues by project/scan item ID",
                },
                scan_item_type: {
                    type: "string",
                    description: "Type of scan item (e.g., project, container_image)",
                    enum: ["project", "container_image"],
                },
                type: {
                    type: "string",
                    description: "Filter by issue type",
                    enum: ["package_vulnerability", "license", "cloud", "code", "config", "custom"],
                },
                effective_severity_level: {
                    type: "array",
                    items: { type: "string" },
                    description: "Filter by severity levels (e.g., ['critical', 'high'])",
                },
                ignored: {
                    type: "boolean",
                    description: "Filter by ignored status",
                },
                limit: {
                    type: "number",
                    description: "Maximum number of issues to return (default: 100)",
                },
            },
            required: [],
        },
    },
    {
        name: "snyk_get_issue",
        description: "Get detailed information about a specific issue",
        inputSchema: {
            type: "object",
            properties: {
                org_id: {
                    type: "string",
                    description: "The organization ID (uses SNYK_ORG_ID env var if not provided)",
                },
                issue_id: {
                    type: "string",
                    description: "The issue ID",
                },
            },
            required: ["issue_id"],
        },
    },
    {
        name: "snyk_get_project_aggregated_issues",
        description: "Get aggregated issues for a project (uses V1 API for detailed vulnerability information)",
        inputSchema: {
            type: "object",
            properties: {
                org_id: {
                    type: "string",
                    description: "The organization ID (uses SNYK_ORG_ID env var if not provided)",
                },
                project_id: {
                    type: "string",
                    description: "The project ID",
                },
                include_description: {
                    type: "boolean",
                    description: "Include issue descriptions (default: true)",
                },
                include_introduced_through: {
                    type: "boolean",
                    description: "Include dependency paths (default: true)",
                },
            },
            required: ["project_id"],
        },
    },
    {
        name: "snyk_list_targets",
        description: "List all targets (repositories, container registries) in an organization",
        inputSchema: {
            type: "object",
            properties: {
                org_id: {
                    type: "string",
                    description: "The organization ID (uses SNYK_ORG_ID env var if not provided)",
                },
                origin: {
                    type: "string",
                    description: "Filter by origin (e.g., github, gitlab, docker-hub)",
                },
                exclude_empty: {
                    type: "boolean",
                    description: "Exclude targets with no projects (default: false)",
                },
                limit: {
                    type: "number",
                    description: "Maximum number of targets to return (default: 100)",
                },
            },
            required: [],
        },
    },
    {
        name: "snyk_test_package",
        description: "Test a package for known vulnerabilities without importing a project",
        inputSchema: {
            type: "object",
            properties: {
                org_id: {
                    type: "string",
                    description: "The organization ID (uses SNYK_ORG_ID env var if not provided)",
                },
                package_manager: {
                    type: "string",
                    description: "Package manager type",
                    enum: ["npm", "maven", "pip", "rubygems", "nuget", "composer", "golang", "cargo"],
                },
                package_name: {
                    type: "string",
                    description: "The package name (e.g., 'lodash' for npm, 'org.apache.logging.log4j:log4j-core' for maven)",
                },
                package_version: {
                    type: "string",
                    description: "The package version to test",
                },
            },
            required: ["package_manager", "package_name", "package_version"],
        },
    },
    {
        name: "snyk_list_package_issues",
        description: "List known vulnerabilities for a package using Package URL (purl)",
        inputSchema: {
            type: "object",
            properties: {
                org_id: {
                    type: "string",
                    description: "The organization ID (uses SNYK_ORG_ID env var if not provided)",
                },
                purl: {
                    type: "string",
                    description: "Package URL (e.g., 'pkg:npm/lodash@4.17.20', 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0')",
                },
            },
            required: ["purl"],
        },
    },
    {
        name: "snyk_get_sbom",
        description: "Export a project's Software Bill of Materials (SBOM) in CycloneDX or SPDX format",
        inputSchema: {
            type: "object",
            properties: {
                org_id: {
                    type: "string",
                    description: "The organization ID (uses SNYK_ORG_ID env var if not provided)",
                },
                project_id: {
                    type: "string",
                    description: "The project ID",
                },
                format: {
                    type: "string",
                    description: "SBOM format",
                    enum: ["cyclonedx+json", "cyclonedx+xml", "spdx+json"],
                    default: "cyclonedx+json",
                },
            },
            required: ["project_id"],
        },
    },
    {
        name: "snyk_list_dependencies",
        description: "List all dependencies for a project (V1 API)",
        inputSchema: {
            type: "object",
            properties: {
                org_id: {
                    type: "string",
                    description: "The organization ID (uses SNYK_ORG_ID env var if not provided)",
                },
                project_id: {
                    type: "string",
                    description: "The project ID",
                },
            },
            required: ["project_id"],
        },
    },
    {
        name: "snyk_ignore_issue",
        description: "Ignore an issue in a project",
        inputSchema: {
            type: "object",
            properties: {
                org_id: {
                    type: "string",
                    description: "The organization ID (uses SNYK_ORG_ID env var if not provided)",
                },
                project_id: {
                    type: "string",
                    description: "The project ID",
                },
                issue_id: {
                    type: "string",
                    description: "The issue ID to ignore",
                },
                reason: {
                    type: "string",
                    description: "Reason for ignoring",
                    enum: ["not-vulnerable", "wont-fix", "temporary-ignore"],
                },
                reason_type: {
                    type: "string",
                    description: "Additional context for the ignore reason",
                },
                expires_at: {
                    type: "string",
                    description: "Expiration date for the ignore (ISO 8601 format)",
                },
                disregard_if_fixable: {
                    type: "boolean",
                    description: "Remove ignore when fix becomes available (default: false)",
                },
            },
            required: ["project_id", "issue_id", "reason"],
        },
    },
    {
        name: "snyk_activate_project",
        description: "Activate a deactivated project to resume monitoring",
        inputSchema: {
            type: "object",
            properties: {
                org_id: {
                    type: "string",
                    description: "The organization ID (uses SNYK_ORG_ID env var if not provided)",
                },
                project_id: {
                    type: "string",
                    description: "The project ID to activate",
                },
            },
            required: ["project_id"],
        },
    },
    {
        name: "snyk_deactivate_project",
        description: "Deactivate a project to pause monitoring",
        inputSchema: {
            type: "object",
            properties: {
                org_id: {
                    type: "string",
                    description: "The organization ID (uses SNYK_ORG_ID env var if not provided)",
                },
                project_id: {
                    type: "string",
                    description: "The project ID to deactivate",
                },
            },
            required: ["project_id"],
        },
    },
    {
        name: "snyk_get_org_entitlements",
        description: "Get the entitlements for an organization (what features are available)",
        inputSchema: {
            type: "object",
            properties: {
                org_id: {
                    type: "string",
                    description: "The organization ID (uses SNYK_ORG_ID env var if not provided)",
                },
            },
            required: [],
        },
    },
    {
        name: "snyk_list_policies",
        description: "List all policies for an organization or group",
        inputSchema: {
            type: "object",
            properties: {
                org_id: {
                    type: "string",
                    description: "The organization ID (uses SNYK_ORG_ID env var if not provided)",
                },
                group_id: {
                    type: "string",
                    description: "The group ID (if listing group-level policies)",
                },
                limit: {
                    type: "number",
                    description: "Maximum number of policies to return (default: 100)",
                },
            },
            required: [],
        },
    },
    {
        name: "snyk_get_policy",
        description: "Get details about a specific policy",
        inputSchema: {
            type: "object",
            properties: {
                policy_id: {
                    type: "string",
                    description: "The policy ID",
                },
                org_id: {
                    type: "string",
                    description: "The organization ID (uses SNYK_ORG_ID env var if not provided)",
                },
                group_id: {
                    type: "string",
                    description: "The group ID (if getting a group-level policy)",
                },
            },
            required: ["policy_id"],
        },
    },
    {
        name: "snyk_create_policy",
        description: "Create a new policy for an organization or group",
        inputSchema: {
            type: "object",
            properties: {
                org_id: {
                    type: "string",
                    description: "The organization ID (uses SNYK_ORG_ID env var if not provided)",
                },
                group_id: {
                    type: "string",
                    description: "The group ID (if creating a group-level policy)",
                },
                name: {
                    type: "string",
                    description: "The policy name",
                },
                action_type: {
                    type: "string",
                    description: "The action type (e.g., 'ignore')",
                },
                action: {
                    type: "object",
                    description: "Action configuration (e.g., {ignore_type: 'temporary', reason: 'false positive'})",
                },
                conditions_group: {
                    type: "object",
                    description: "Conditions group defining when the policy applies",
                },
            },
            required: ["name", "action_type"],
        },
    },
    {
        name: "snyk_update_policy",
        description: "Update an existing policy",
        inputSchema: {
            type: "object",
            properties: {
                policy_id: {
                    type: "string",
                    description: "The policy ID to update",
                },
                org_id: {
                    type: "string",
                    description: "The organization ID (uses SNYK_ORG_ID env var if not provided)",
                },
                group_id: {
                    type: "string",
                    description: "The group ID (if updating a group-level policy)",
                },
                name: {
                    type: "string",
                    description: "The policy name",
                },
                action_type: {
                    type: "string",
                    description: "The action type (e.g., 'ignore')",
                },
                action: {
                    type: "object",
                    description: "Action configuration",
                },
                conditions_group: {
                    type: "object",
                    description: "Conditions group defining when the policy applies",
                },
            },
            required: ["policy_id"],
        },
    },
];
// Tool handlers
async function handleVerifyToken() {
    const credError = checkCredentials();
    if (credError)
        return credError;
    const v1Client = createV1Client();
    try {
        const response = await v1Client.get("/user/me");
        const user = response.data;
        return JSON.stringify({
            success: true,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                name: user.name,
            },
        }, null, 2);
    }
    catch (error) {
        return JSON.stringify({
            success: false,
            error: formatError(error),
        }, null, 2);
    }
}
async function handleListOrgs(args) {
    const credError = checkCredentials();
    if (credError)
        return credError;
    const client = createRestClient();
    const limit = args.limit || 100;
    try {
        const orgs = await fetchAllPages(client, `/orgs?limit=${Math.min(limit, 100)}`, Math.ceil(limit / 100));
        return JSON.stringify({
            count: orgs.length,
            organizations: orgs.slice(0, limit).map(org => ({
                id: org.id,
                name: org.attributes.name,
                slug: org.attributes.slug,
                group_id: org.attributes.group_id,
                is_personal: org.attributes.is_personal,
            })),
        }, null, 2);
    }
    catch (error) {
        return JSON.stringify({ error: formatError(error) }, null, 2);
    }
}
async function handleGetOrg(args) {
    const credError = checkCredentials();
    if (credError)
        return credError;
    const client = createRestClient();
    const orgId = args.org_id || SNYK_ORG_ID;
    if (!orgId) {
        return JSON.stringify({ error: "org_id is required (set SNYK_ORG_ID or provide org_id parameter)" }, null, 2);
    }
    try {
        const response = await client.get(`/orgs/${orgId}`);
        const org = response.data.data;
        return JSON.stringify({
            id: org.id,
            name: org.attributes.name,
            slug: org.attributes.slug,
            group_id: org.attributes.group_id,
            is_personal: org.attributes.is_personal,
            created: org.attributes.created,
        }, null, 2);
    }
    catch (error) {
        return JSON.stringify({ error: formatError(error) }, null, 2);
    }
}
async function handleListProjects(args) {
    const credError = checkCredentials();
    if (credError)
        return credError;
    const client = createRestClient();
    const orgId = args.org_id || SNYK_ORG_ID;
    if (!orgId) {
        return JSON.stringify({ error: "org_id is required (set SNYK_ORG_ID or provide org_id parameter)" }, null, 2);
    }
    const limit = args.limit || 100;
    const params = new URLSearchParams();
    params.append("limit", String(Math.min(limit, 100)));
    if (args.target_id)
        params.append("target_id", args.target_id);
    if (args.origin)
        params.append("origin", args.origin);
    if (args.type)
        params.append("type", args.type);
    try {
        const projects = await fetchAllPages(client, `/orgs/${orgId}/projects?${params.toString()}`, Math.ceil(limit / 100));
        return JSON.stringify({
            count: projects.length,
            projects: projects.slice(0, limit).map(proj => ({
                id: proj.id,
                name: proj.attributes.name,
                type: proj.attributes.type,
                origin: proj.attributes.origin,
                target_reference: proj.attributes.target_reference,
                status: proj.attributes.status,
                created: proj.attributes.created,
                business_criticality: proj.attributes.business_criticality,
                environment: proj.attributes.environment,
                lifecycle: proj.attributes.lifecycle,
            })),
        }, null, 2);
    }
    catch (error) {
        return JSON.stringify({ error: formatError(error) }, null, 2);
    }
}
async function handleGetProject(args) {
    const credError = checkCredentials();
    if (credError)
        return credError;
    const client = createRestClient();
    const orgId = args.org_id || SNYK_ORG_ID;
    if (!orgId) {
        return JSON.stringify({ error: "org_id is required (set SNYK_ORG_ID or provide org_id parameter)" }, null, 2);
    }
    try {
        const response = await client.get(`/orgs/${orgId}/projects/${args.project_id}`);
        const proj = response.data.data;
        return JSON.stringify({
            id: proj.id,
            name: proj.attributes.name,
            type: proj.attributes.type,
            origin: proj.attributes.origin,
            target_reference: proj.attributes.target_reference,
            status: proj.attributes.status,
            created: proj.attributes.created,
            business_criticality: proj.attributes.business_criticality,
            environment: proj.attributes.environment,
            lifecycle: proj.attributes.lifecycle,
            relationships: proj.relationships,
        }, null, 2);
    }
    catch (error) {
        return JSON.stringify({ error: formatError(error) }, null, 2);
    }
}
async function handleListIssues(args) {
    const credError = checkCredentials();
    if (credError)
        return credError;
    const client = createRestClient();
    const orgId = args.org_id || SNYK_ORG_ID;
    if (!orgId) {
        return JSON.stringify({ error: "org_id is required (set SNYK_ORG_ID or provide org_id parameter)" }, null, 2);
    }
    const limit = args.limit || 100;
    const params = new URLSearchParams();
    params.append("limit", String(Math.min(limit, 100)));
    if (args.scan_item_id && args.scan_item_type) {
        params.append("scan_item.id", args.scan_item_id);
        params.append("scan_item.type", args.scan_item_type);
    }
    if (args.type)
        params.append("type", args.type);
    if (args.effective_severity_level) {
        args.effective_severity_level.forEach(level => {
            params.append("effective_severity_level", level);
        });
    }
    if (args.ignored !== undefined)
        params.append("ignored", String(args.ignored));
    try {
        const issues = await fetchAllPages(client, `/orgs/${orgId}/issues?${params.toString()}`, Math.ceil(limit / 100));
        return JSON.stringify({
            count: issues.length,
            issues: issues.slice(0, limit).map(issue => ({
                id: issue.id,
                title: issue.attributes.title,
                type: issue.attributes.type,
                severity: issue.attributes.effective_severity_level,
                status: issue.attributes.status,
                ignored: issue.attributes.ignored,
                problems: issue.attributes.problems,
            })),
        }, null, 2);
    }
    catch (error) {
        return JSON.stringify({ error: formatError(error) }, null, 2);
    }
}
async function handleGetIssue(args) {
    const credError = checkCredentials();
    if (credError)
        return credError;
    const client = createRestClient();
    const orgId = args.org_id || SNYK_ORG_ID;
    if (!orgId) {
        return JSON.stringify({ error: "org_id is required (set SNYK_ORG_ID or provide org_id parameter)" }, null, 2);
    }
    try {
        const response = await client.get(`/orgs/${orgId}/issues/${args.issue_id}`);
        const issue = response.data.data;
        return JSON.stringify({
            id: issue.id,
            title: issue.attributes.title,
            type: issue.attributes.type,
            severity: issue.attributes.effective_severity_level,
            status: issue.attributes.status,
            ignored: issue.attributes.ignored,
            problems: issue.attributes.problems,
            coordinates: issue.attributes.coordinates,
        }, null, 2);
    }
    catch (error) {
        return JSON.stringify({ error: formatError(error) }, null, 2);
    }
}
async function handleGetProjectAggregatedIssues(args) {
    const credError = checkCredentials();
    if (credError)
        return credError;
    const v1Client = createV1Client();
    const orgId = args.org_id || SNYK_ORG_ID;
    if (!orgId) {
        return JSON.stringify({ error: "org_id is required (set SNYK_ORG_ID or provide org_id parameter)" }, null, 2);
    }
    try {
        const response = await v1Client.post(`/org/${orgId}/project/${args.project_id}/aggregated-issues`, {
            includeDescription: args.include_description !== false,
            includeIntroducedThrough: args.include_introduced_through !== false,
        });
        return JSON.stringify({
            issues: response.data.issues,
        }, null, 2);
    }
    catch (error) {
        return JSON.stringify({ error: formatError(error) }, null, 2);
    }
}
async function handleListTargets(args) {
    const credError = checkCredentials();
    if (credError)
        return credError;
    const client = createRestClient();
    const orgId = args.org_id || SNYK_ORG_ID;
    if (!orgId) {
        return JSON.stringify({ error: "org_id is required (set SNYK_ORG_ID or provide org_id parameter)" }, null, 2);
    }
    const limit = args.limit || 100;
    const params = new URLSearchParams();
    params.append("limit", String(Math.min(limit, 100)));
    if (args.origin)
        params.append("origin", args.origin);
    if (args.exclude_empty)
        params.append("exclude_empty", String(args.exclude_empty));
    try {
        const targets = await fetchAllPages(client, `/orgs/${orgId}/targets?${params.toString()}`, Math.ceil(limit / 100));
        return JSON.stringify({
            count: targets.length,
            targets: targets.slice(0, limit).map(target => ({
                id: target.id,
                display_name: target.attributes.display_name,
                url: target.attributes.url,
                created_at: target.attributes.created_at,
                is_private: target.attributes.is_private,
            })),
        }, null, 2);
    }
    catch (error) {
        return JSON.stringify({ error: formatError(error) }, null, 2);
    }
}
async function handleTestPackage(args) {
    const credError = checkCredentials();
    if (credError)
        return credError;
    const v1Client = createV1Client();
    const orgId = args.org_id || SNYK_ORG_ID;
    const endpoints = {
        npm: "npm",
        maven: "maven",
        pip: "pip",
        rubygems: "rubygems",
        nuget: "nuget",
        composer: "composer",
        golang: "golangdep",
        cargo: "cargo",
    };
    const endpoint = endpoints[args.package_manager];
    if (!endpoint) {
        return JSON.stringify({ error: `Unsupported package manager: ${args.package_manager}` }, null, 2);
    }
    try {
        let url = `/test/${endpoint}/${encodeURIComponent(args.package_name)}/${encodeURIComponent(args.package_version)}`;
        if (orgId) {
            url += `?org=${orgId}`;
        }
        const response = await v1Client.get(url);
        return JSON.stringify({
            ok: response.data.ok,
            issues_count: response.data.issues?.vulnerabilities?.length || 0,
            vulnerabilities: response.data.issues?.vulnerabilities?.map((v) => ({
                id: v.id,
                title: v.title,
                severity: v.severity,
                cvssScore: v.cvssScore,
                exploit: v.exploit,
                fixedIn: v.fixedIn,
            })),
            licenses: response.data.issues?.licenses,
            package_info: {
                name: response.data.packageManager,
                version: args.package_version,
            },
        }, null, 2);
    }
    catch (error) {
        return JSON.stringify({ error: formatError(error) }, null, 2);
    }
}
async function handleListPackageIssues(args) {
    const credError = checkCredentials();
    if (credError)
        return credError;
    const client = createRestClient();
    const orgId = args.org_id || SNYK_ORG_ID;
    if (!orgId) {
        return JSON.stringify({ error: "org_id is required (set SNYK_ORG_ID or provide org_id parameter)" }, null, 2);
    }
    try {
        const encodedPurl = encodeURIComponent(args.purl);
        const response = await client.get(`/orgs/${orgId}/packages/${encodedPurl}/issues`);
        return JSON.stringify({
            purl: args.purl,
            issues: response.data.data?.map((issue) => ({
                id: issue.id,
                title: issue.attributes.title,
                type: issue.attributes.type,
                severity: issue.attributes.effective_severity_level,
            })),
        }, null, 2);
    }
    catch (error) {
        return JSON.stringify({ error: formatError(error) }, null, 2);
    }
}
async function handleGetSbom(args) {
    const credError = checkCredentials();
    if (credError)
        return credError;
    const client = createRestClient();
    const orgId = args.org_id || SNYK_ORG_ID;
    if (!orgId) {
        return JSON.stringify({ error: "org_id is required (set SNYK_ORG_ID or provide org_id parameter)" }, null, 2);
    }
    const format = args.format || "cyclonedx+json";
    try {
        const response = await client.get(`/orgs/${orgId}/projects/${args.project_id}/sbom`, {
            params: { format },
            headers: {
                Accept: format.includes("json") ? "application/json" : "application/xml",
            },
        });
        return JSON.stringify(response.data, null, 2);
    }
    catch (error) {
        return JSON.stringify({ error: formatError(error) }, null, 2);
    }
}
async function handleListDependencies(args) {
    const credError = checkCredentials();
    if (credError)
        return credError;
    const v1Client = createV1Client();
    const orgId = args.org_id || SNYK_ORG_ID;
    if (!orgId) {
        return JSON.stringify({ error: "org_id is required (set SNYK_ORG_ID or provide org_id parameter)" }, null, 2);
    }
    try {
        const response = await v1Client.post(`/org/${orgId}/project/${args.project_id}/dep-graph`);
        return JSON.stringify({
            project_id: args.project_id,
            dep_graph: response.data.depGraph,
        }, null, 2);
    }
    catch (error) {
        // Try alternative endpoint
        try {
            const altResponse = await v1Client.get(`/org/${orgId}/dependencies`, {
                params: { projectIds: args.project_id },
            });
            return JSON.stringify({
                project_id: args.project_id,
                dependencies: altResponse.data.results,
                total: altResponse.data.total,
            }, null, 2);
        }
        catch (altError) {
            return JSON.stringify({ error: formatError(error) }, null, 2);
        }
    }
}
async function handleIgnoreIssue(args) {
    const credError = checkCredentials();
    if (credError)
        return credError;
    const v1Client = createV1Client();
    const orgId = args.org_id || SNYK_ORG_ID;
    if (!orgId) {
        return JSON.stringify({ error: "org_id is required (set SNYK_ORG_ID or provide org_id parameter)" }, null, 2);
    }
    try {
        const payload = {
            reason: args.reason,
        };
        if (args.reason_type)
            payload.reasonType = args.reason_type;
        if (args.expires_at)
            payload.expires = args.expires_at;
        if (args.disregard_if_fixable !== undefined)
            payload.disregardIfFixable = args.disregard_if_fixable;
        const response = await v1Client.post(`/org/${orgId}/project/${args.project_id}/ignore/${args.issue_id}`, payload);
        return JSON.stringify({
            success: true,
            ignore: response.data,
        }, null, 2);
    }
    catch (error) {
        return JSON.stringify({ error: formatError(error) }, null, 2);
    }
}
async function handleActivateProject(args) {
    const credError = checkCredentials();
    if (credError)
        return credError;
    const v1Client = createV1Client();
    const orgId = args.org_id || SNYK_ORG_ID;
    if (!orgId) {
        return JSON.stringify({ error: "org_id is required (set SNYK_ORG_ID or provide org_id parameter)" }, null, 2);
    }
    try {
        await v1Client.post(`/org/${orgId}/project/${args.project_id}/activate`);
        return JSON.stringify({
            success: true,
            message: `Project ${args.project_id} has been activated`,
        }, null, 2);
    }
    catch (error) {
        return JSON.stringify({ error: formatError(error) }, null, 2);
    }
}
async function handleDeactivateProject(args) {
    const credError = checkCredentials();
    if (credError)
        return credError;
    const v1Client = createV1Client();
    const orgId = args.org_id || SNYK_ORG_ID;
    if (!orgId) {
        return JSON.stringify({ error: "org_id is required (set SNYK_ORG_ID or provide org_id parameter)" }, null, 2);
    }
    try {
        await v1Client.post(`/org/${orgId}/project/${args.project_id}/deactivate`);
        return JSON.stringify({
            success: true,
            message: `Project ${args.project_id} has been deactivated`,
        }, null, 2);
    }
    catch (error) {
        return JSON.stringify({ error: formatError(error) }, null, 2);
    }
}
async function handleGetOrgEntitlements(args) {
    const credError = checkCredentials();
    if (credError)
        return credError;
    const v1Client = createV1Client();
    const orgId = args.org_id || SNYK_ORG_ID;
    if (!orgId) {
        return JSON.stringify({ error: "org_id is required (set SNYK_ORG_ID or provide org_id parameter)" }, null, 2);
    }
    try {
        const response = await v1Client.get(`/org/${orgId}/entitlements`);
        return JSON.stringify(response.data, null, 2);
    }
    catch (error) {
        return JSON.stringify({ error: formatError(error) }, null, 2);
    }
}
async function handleListPolicies(args) {
    const credError = checkCredentials();
    if (credError)
        return credError;
    const client = createRestClient();
    const limit = args.limit || 100;
    let baseUrl;
    if (args.group_id) {
        baseUrl = `/groups/${args.group_id}/policies`;
    }
    else {
        const orgId = args.org_id || SNYK_ORG_ID;
        if (!orgId) {
            return JSON.stringify({ error: "org_id or group_id is required (set SNYK_ORG_ID or provide org_id/group_id parameter)" }, null, 2);
        }
        baseUrl = `/orgs/${orgId}/policies`;
    }
    try {
        const policies = await fetchAllPages(client, `${baseUrl}?limit=${Math.min(limit, 100)}`, Math.ceil(limit / 100));
        return JSON.stringify({
            count: policies.length,
            policies: policies.slice(0, limit).map(policy => ({
                id: policy.id,
                name: policy.attributes.name,
                action_type: policy.attributes.action_type,
                action: policy.attributes.action,
                conditions_group: policy.attributes.conditions_group,
                review: policy.attributes.review,
                created_at: policy.attributes.created_at,
                updated_at: policy.attributes.updated_at,
            })),
        }, null, 2);
    }
    catch (error) {
        return JSON.stringify({ error: formatError(error) }, null, 2);
    }
}
async function handleGetPolicy(args) {
    const credError = checkCredentials();
    if (credError)
        return credError;
    const client = createRestClient();
    let url;
    if (args.group_id) {
        url = `/groups/${args.group_id}/policies/${args.policy_id}`;
    }
    else {
        const orgId = args.org_id || SNYK_ORG_ID;
        if (!orgId) {
            return JSON.stringify({ error: "org_id or group_id is required (set SNYK_ORG_ID or provide org_id/group_id parameter)" }, null, 2);
        }
        url = `/orgs/${orgId}/policies/${args.policy_id}`;
    }
    try {
        const response = await client.get(url);
        const policy = response.data.data;
        return JSON.stringify({
            id: policy.id,
            name: policy.attributes.name,
            action_type: policy.attributes.action_type,
            action: policy.attributes.action,
            conditions_group: policy.attributes.conditions_group,
            review: policy.attributes.review,
            created_at: policy.attributes.created_at,
            updated_at: policy.attributes.updated_at,
        }, null, 2);
    }
    catch (error) {
        return JSON.stringify({ error: formatError(error) }, null, 2);
    }
}
async function handleCreatePolicy(args) {
    const credError = checkCredentials();
    if (credError)
        return credError;
    const client = createRestClient();
    let url;
    if (args.group_id) {
        url = `/groups/${args.group_id}/policies`;
    }
    else {
        const orgId = args.org_id || SNYK_ORG_ID;
        if (!orgId) {
            return JSON.stringify({ error: "org_id or group_id is required (set SNYK_ORG_ID or provide org_id/group_id parameter)" }, null, 2);
        }
        url = `/orgs/${orgId}/policies`;
    }
    try {
        const payload = {
            data: {
                type: "policy",
                attributes: {
                    name: args.name,
                    action_type: args.action_type,
                    ...(args.action && { action: args.action }),
                    ...(args.conditions_group && { conditions_group: args.conditions_group }),
                },
            },
        };
        const response = await client.post(url, payload);
        const policy = response.data.data;
        return JSON.stringify({
            success: true,
            policy: {
                id: policy.id,
                name: policy.attributes.name,
                action_type: policy.attributes.action_type,
                action: policy.attributes.action,
                conditions_group: policy.attributes.conditions_group,
            },
        }, null, 2);
    }
    catch (error) {
        return JSON.stringify({ error: formatError(error) }, null, 2);
    }
}
async function handleUpdatePolicy(args) {
    const credError = checkCredentials();
    if (credError)
        return credError;
    const client = createRestClient();
    let url;
    if (args.group_id) {
        url = `/groups/${args.group_id}/policies/${args.policy_id}`;
    }
    else {
        const orgId = args.org_id || SNYK_ORG_ID;
        if (!orgId) {
            return JSON.stringify({ error: "org_id or group_id is required (set SNYK_ORG_ID or provide org_id/group_id parameter)" }, null, 2);
        }
        url = `/orgs/${orgId}/policies/${args.policy_id}`;
    }
    try {
        const payload = {
            data: {
                type: "policy",
                id: args.policy_id,
                attributes: {
                    ...(args.name && { name: args.name }),
                    ...(args.action_type && { action_type: args.action_type }),
                    ...(args.action && { action: args.action }),
                    ...(args.conditions_group && { conditions_group: args.conditions_group }),
                },
            },
        };
        const response = await client.patch(url, payload);
        const policy = response.data.data;
        return JSON.stringify({
            success: true,
            policy: {
                id: policy.id,
                name: policy.attributes.name,
                action_type: policy.attributes.action_type,
                action: policy.attributes.action,
                conditions_group: policy.attributes.conditions_group,
                updated_at: policy.attributes.updated_at,
            },
        }, null, 2);
    }
    catch (error) {
        return JSON.stringify({ error: formatError(error) }, null, 2);
    }
}
// Main server setup
async function main() {
    const server = new Server({
        name: "snyk-mcp",
        version: "1.0.0",
    }, {
        capabilities: {
            tools: {},
        },
    });
    // Handle tool listing
    server.setRequestHandler(ListToolsRequestSchema, async () => {
        return { tools };
    });
    // Handle tool execution
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
        const { name, arguments: args } = request.params;
        try {
            let result;
            switch (name) {
                case "snyk_verify_token":
                    result = await handleVerifyToken();
                    break;
                case "snyk_list_orgs":
                    result = await handleListOrgs(args);
                    break;
                case "snyk_get_org":
                    result = await handleGetOrg(args);
                    break;
                case "snyk_list_projects":
                    result = await handleListProjects(args);
                    break;
                case "snyk_get_project":
                    result = await handleGetProject(args);
                    break;
                case "snyk_list_issues":
                    result = await handleListIssues(args);
                    break;
                case "snyk_get_issue":
                    result = await handleGetIssue(args);
                    break;
                case "snyk_get_project_aggregated_issues":
                    result = await handleGetProjectAggregatedIssues(args);
                    break;
                case "snyk_list_targets":
                    result = await handleListTargets(args);
                    break;
                case "snyk_test_package":
                    result = await handleTestPackage(args);
                    break;
                case "snyk_list_package_issues":
                    result = await handleListPackageIssues(args);
                    break;
                case "snyk_get_sbom":
                    result = await handleGetSbom(args);
                    break;
                case "snyk_list_dependencies":
                    result = await handleListDependencies(args);
                    break;
                case "snyk_ignore_issue":
                    result = await handleIgnoreIssue(args);
                    break;
                case "snyk_activate_project":
                    result = await handleActivateProject(args);
                    break;
                case "snyk_deactivate_project":
                    result = await handleDeactivateProject(args);
                    break;
                case "snyk_get_org_entitlements":
                    result = await handleGetOrgEntitlements(args);
                    break;
                case "snyk_list_policies":
                    result = await handleListPolicies(args);
                    break;
                case "snyk_get_policy":
                    result = await handleGetPolicy(args);
                    break;
                case "snyk_create_policy":
                    result = await handleCreatePolicy(args);
                    break;
                case "snyk_update_policy":
                    result = await handleUpdatePolicy(args);
                    break;
                default:
                    return {
                        content: [{ type: "text", text: `Unknown tool: ${name}` }],
                        isError: true,
                    };
            }
            return {
                content: [{ type: "text", text: result }],
            };
        }
        catch (error) {
            return {
                content: [{ type: "text", text: `Error: ${formatError(error)}` }],
                isError: true,
            };
        }
    });
    // Start the server
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("Snyk MCP Server started successfully");
}
main().catch((error) => {
    console.error("Failed to start server:", error);
    process.exit(1);
});
//# sourceMappingURL=index.js.map