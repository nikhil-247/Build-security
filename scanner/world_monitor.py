from __future__ import annotations

WORLD_MONITOR_PROFILE = {
    "name": "World Monitor",
    "problem_statement": "26163",
    "target_profile": "worldmonitor.app",
    "official_surfaces": [
        {
            "id": "web",
            "label": "Web / PWA",
            "host": "worldmonitor.app",
            "type": "client",
            "scope": "Client-side security controls",
            "description": "Browser-facing intelligence dashboard and progressive web app surface.",
        },
        {
            "id": "auth",
            "label": "Authentication",
            "host": "worldmonitor.app",
            "type": "security",
            "scope": "Authentication and session management",
            "description": "Browser session plus documented API-key/OAuth authentication boundary.",
        },
        {
            "id": "rest",
            "label": "REST API",
            "host": "api.worldmonitor.app",
            "type": "api",
            "scope": "API security",
            "description": "Publicly documented REST API surface for programmatic access.",
        },
        {
            "id": "mcp",
            "label": "MCP",
            "host": "worldmonitor.app/mcp",
            "type": "api",
            "scope": "API security",
            "description": "MCP transport surface documented by the project.",
        },
        {
            "id": "clients",
            "label": "CLI / SDK",
            "host": "npm + language SDKs",
            "type": "client",
            "scope": "Input validation and data handling",
            "description": "Programmatic client surfaces consuming the same API contracts.",
        },
        {
            "id": "data",
            "label": "Data services",
            "host": "service domains + sources",
            "type": "data",
            "scope": "Data storage and privacy protections",
            "description": "Live service/data flow that feeds the monitoring dashboard.",
        },
    ],
    "edges": [
        ["web", "auth"], ["auth", "rest"], ["auth", "mcp"],
        ["clients", "rest"], ["clients", "mcp"], ["rest", "data"], ["mcp", "data"],
    ],
}

def profile_for_target(target: str) -> dict:
    return WORLD_MONITOR_PROFILE

def attack_surface_summary(findings) -> dict:
    counts = {node["id"]: 0 for node in WORLD_MONITOR_PROFILE["official_surfaces"]}
    labels = {node["id"]: node["label"] for node in WORLD_MONITOR_PROFILE["official_surfaces"]}
    map_by_surface = {
        "Web Client": "web",
        "Auth / Session": "auth",
        "REST API": "rest",
        "Web / Transport": "web",
        "Application Core": "data",
    }
    for finding in findings:
        node = map_by_surface.get(finding.attack_surface, "data")
        counts[node] = counts.get(node, 0) + 1
    return {"nodes": WORLD_MONITOR_PROFILE["official_surfaces"], "edges": WORLD_MONITOR_PROFILE["edges"], "finding_counts": counts, "labels": labels}
