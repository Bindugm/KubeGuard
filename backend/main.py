from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
import json
import requests

from kubernetes import client, config


app = FastAPI(
    title="KubeGuard AI",
    description="AI-powered Kubernetes security and DevSecOps platform",
    version="0.1.0",
)


# --------------------------------------------------
# Configuration
# --------------------------------------------------

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
OLLAMA_MODEL = "mistral"


# --------------------------------------------------
# Request Models
# --------------------------------------------------

class ScanRequest(BaseModel):
    image: str


class AIRequest(BaseModel):
    finding: str


# --------------------------------------------------
# Root
# --------------------------------------------------

@app.get("/")
def root():
    return {
        "name": "KubeGuard AI",
        "status": "running",
        "version": "0.1.0",
    }


# --------------------------------------------------
# Health Check
# --------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


# --------------------------------------------------
# Trivy Image Scan
# --------------------------------------------------

@app.post("/scan/image")
def scan_image(request: ScanRequest):
    try:
        result = subprocess.run(
            [
                "trivy",
                "image",
                "--format",
                "json",
                "--quiet",
                request.image,
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=result.stderr.strip() or "Trivy scan failed",
            )

        return json.loads(result.stdout)

    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=504,
            detail="Trivy scan timed out",
        )

    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500,
            detail="Trivy returned invalid JSON",
        )


# --------------------------------------------------
# Ollama / Mistral AI Analysis
# --------------------------------------------------

@app.post("/ai/analyze")
def analyze_finding(request: AIRequest):

    prompt = f"""
You are KubeGuard AI, a Kubernetes security assistant.

Analyze this security finding:

{request.finding}

Provide:

1. A short explanation of the issue.
2. Why it matters.
3. Recommended remediation.
4. A concrete Kubernetes or Docker remediation example when applicable.

Keep the response practical and concise.
"""

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
            },
            timeout=300,
        )

        response.raise_for_status()

        return {
            "model": OLLAMA_MODEL,
            "analysis": response.json().get(
                "response",
                ""
            ),
        }

    except requests.RequestException as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Ollama request failed: {exc}",
        )


# --------------------------------------------------
# Falco Runtime Security Events
# --------------------------------------------------

@app.get("/runtime/events")
def runtime_events():

    import re

    try:
        config.load_kube_config()

        core_api = client.CoreV1Api()

        pods = core_api.list_pod_for_all_namespaces(
            label_selector="app.kubernetes.io/name=falco"
        )

        events = []

        # Falco standard output format:
        # 14:26:27.598678318: Notice Rule Name | key=value key=value
        event_pattern = re.compile(
            r"^(?P<timestamp>\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
            r"\s*:\s*"
            r"(?P<severity>\w+)"
            r"\s+"
            r"(?P<rule>[^|]+?)"
            r"(?:\s*\|\s*(?P<fields>.*))?$"
        )

        for pod in pods.items:

            namespace = pod.metadata.namespace
            pod_name = pod.metadata.name

            try:
                logs = core_api.read_namespaced_pod_log(
                    name=pod_name,
                    namespace=namespace,
                    container="falco",
                    tail_lines=50,
                )

                if isinstance(logs, bytes):
                    logs = logs.decode(
                        "utf-8",
                        errors="replace"
                    )

                logs = logs.strip()

                # The current Falco output is arriving with
                # literal "\n" characters.
                logs = logs.replace("\\n", "\n")

            except Exception as exc:

                events.append({
                    "timestamp": "",
                    "severity": "error",
                    "rule": "Falco log retrieval failed",
                    "pod": pod_name,
                    "namespace": namespace,
                    "event": str(exc),
                })

                continue

            for line in logs.splitlines():

                line = line.strip()

                if not line:
                    continue

                match = event_pattern.match(line)

                # Ignore lines that are not standard Falco events
                if not match:
                    continue

                timestamp = match.group("timestamp")
                severity = match.group("severity")
                rule = match.group("rule").strip()
                fields_text = match.group("fields") or ""

                # Parse Falco key=value fields
                fields = {}

                for key, value in re.findall(
                    r'(\w+)=((?:"[^"]*")|(?:\S+))',
                    fields_text
                ):
                    value = value.strip('"')
                    fields[key] = value

                # Use the Kubernetes workload from the Falco event.
                event_pod = fields.get(
                    "k8s_pod_name",
                    pod_name
                )

                event_namespace = fields.get(
                    "k8s_ns_name",
                    namespace
                )

                events.append({
                    "timestamp": timestamp,
                    "severity": severity,
                    "rule": rule,
                    "pod": event_pod,
                    "namespace": event_namespace,
                    "process": fields.get("process", ""),
                    "command": fields.get("command", ""),
                    "container": fields.get("container_name", ""),
                    "container_id": fields.get("container_id", ""),
                    "image": fields.get(
                        "container_image_repository",
                        ""
                    ),
                    "image_tag": fields.get(
                        "container_image_tag",
                        ""
                    ),
                    "event": line,
                })

        return {
            "source": "falco",
            "count": len(events),
            "events": events,
        }

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve Falco events: {exc}",
        )
# --------------------------------------------------
# Gatekeeper Policy Violations
# --------------------------------------------------

@app.get("/policy/violations")
def policy_violations():

    try:
        result = subprocess.run(
            [
                "kubectl",
                "get",
                "k8srequiredresources",
                "-o",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=result.stderr.strip()
                or "Failed to retrieve Gatekeeper constraints",
            )

        data = json.loads(result.stdout)

        violations = []

        for constraint in data.get("items", []):

            constraint_name = constraint.get(
                "metadata",
                {}
            ).get("name", "")

            enforcement_action = constraint.get(
                "spec",
                {}
            ).get(
                "enforcementAction",
                "deny"
            )

            status = constraint.get(
                "status",
                {}
            )

            for violation in status.get(
                "violations",
                []
            ):

                violations.append({
                    "constraint": constraint_name,
                    "enforcement_action": enforcement_action,
                    "kind": violation.get("kind", ""),
                    "name": violation.get("name", ""),
                    "namespace": violation.get(
                        "namespace",
                        ""
                    ),
                    "message": violation.get(
                        "message",
                        ""
                    ),
                })

        return {
            "source": "gatekeeper",
            "count": len(violations),
            "violations": violations,
        }

    except subprocess.TimeoutExpired:

        raise HTTPException(
            status_code=504,
            detail="Gatekeeper query timed out",
        )

    except json.JSONDecodeError:

        raise HTTPException(
            status_code=500,
            detail="Gatekeeper returned invalid JSON",
        )

    except HTTPException:
        raise

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve Gatekeeper violations: {exc}",
        )
@app.get("/gitops/status")
def gitops_status():
    try:
        result = subprocess.run(
            [
                "kubectl",
                "get",
                "applications.argoproj.io",
                "-A",
                "-o",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=result.stderr.strip()
                or "Failed to retrieve ArgoCD applications",
            )

        data = json.loads(result.stdout)

        applications = []

        for app in data.get("items", []):
            metadata = app.get("metadata", {})
            spec = app.get("spec", {})
            status = app.get("status", {})

            applications.append({
                "name": metadata.get("name", ""),
                "namespace": metadata.get("namespace", ""),
                "project": spec.get("project", ""),
                "repo": spec.get("source", {}).get("repoURL", ""),
                "path": spec.get("source", {}).get("path", ""),
                "sync_status": status.get("sync", {}).get("status", ""),
                "health_status": status.get("health", {}).get("status", ""),
                "revision": status.get("sync", {}).get("revision", ""),
            })

        return {
            "source": "argocd",
            "count": len(applications),
            "applications": applications,
        }

    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=504,
            detail="ArgoCD query timed out",
        )

    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500,
            detail="ArgoCD returned invalid JSON",
        )

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve ArgoCD status: {exc}",
        )