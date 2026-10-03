"""Minimal client for the Wazuh Manager's REST API (same server, localhost only)."""

import base64

import httpx

from app.core.config import settings


class WazuhError(Exception):
    pass


def _client() -> httpx.Client:
    # The API listens only on localhost with a self-signed certificate.
    return httpx.Client(base_url=settings.wazuh_api_url, verify=False, timeout=15)


def _token(client: httpx.Client) -> str:
    response = client.post(
        "/security/user/authenticate",
        params={"raw": "true"},
        auth=(settings.wazuh_api_user, settings.wazuh_api_password),
    )
    if response.status_code != 200:
        raise WazuhError(f"Wazuh API login failed ({response.status_code})")
    return response.text.strip()


def _request(method: str, path: str, **kwargs) -> dict:
    try:
        with _client() as client:
            headers = {"Authorization": f"Bearer {_token(client)}"}
            response = client.request(method, path, headers=headers, **kwargs)
    except httpx.HTTPError as exc:
        raise WazuhError(f"Wazuh API unreachable: {exc}") from exc
    body = response.json() if response.content else {}
    if response.status_code >= 400 or body.get("error", 0) != 0:
        raise WazuhError(f"Wazuh API {method} {path} failed: {response.status_code} {body}")
    return body


def add_agent(name: str) -> str:
    """Pre-registers an agent and returns its new id. The agent can only
    connect once its key is installed on the endpoint."""
    body = _request("POST", "/agents", json={"name": name})
    return body["data"]["id"]


def get_agent_key_line(agent_id: str) -> str:
    """The decoded client.keys line ("<id> <name> <ip> <secret>") for an agent."""
    body = _request("GET", f"/agents/{agent_id}/key")
    key = body["data"]["affected_items"][0]["key"]
    return base64.b64decode(key).decode("ascii").strip()


def get_agents_info(agent_ids: list[str]) -> dict[str, dict]:
    """Live status of several agents in one call, keyed by agent id. Each
    value has Wazuh's own fields: status (active / disconnected /
    never_connected / pending), ip, os {name, version}, version, lastKeepAlive."""
    if not agent_ids:
        return {}
    body = _request(
        "GET",
        "/agents",
        params={
            "agents_list": ",".join(agent_ids),
            "select": "status,ip,os.name,os.version,version,lastKeepAlive",
            "limit": len(agent_ids),
        },
    )
    return {item["id"]: item for item in body["data"]["affected_items"]}


def delete_agent(agent_id: str) -> None:
    """Removes the agent, so its key stops working immediately."""
    _request(
        "DELETE",
        "/agents",
        params={"agents_list": agent_id, "status": "all", "older_than": "0s"},
    )
