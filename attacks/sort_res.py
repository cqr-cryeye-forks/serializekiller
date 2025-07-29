from typing import List, Dict
from urllib.parse import urlparse
from collections import defaultdict

def merge_results_from_file(results: List[dict], target: str) -> dict:
    final: Dict[str, any] = {"target": target}

    vuln_entries = []
    has_not_vuln = False
    has_conn_err = False

    all_services = defaultdict(lambda: {
        "urls": [],
        "description": "",
        "proto_ports": defaultdict(set)
    })

    for entry in results:
        status = entry.get("status")
        service = entry.get("service")
        url = entry.get("url")

        parsed = urlparse(url)
        proto = parsed.scheme
        port = parsed.port
        if proto and port:
            all_services[service]["proto_ports"][proto].add(port)

        if status == "Vulnerability":
            vuln_entries.append(entry)
        elif status == "Not vulnerability":
            has_not_vuln = True
        elif status == "Connection error":
            has_conn_err = True

    if vuln_entries:
        final["status"] = "Vulnerability"
        for entry in vuln_entries:
            service = entry["service"]
            url = entry["url"]
            # proto = urlparse(url).scheme
            # port = urlparse(url).port

            all_services[service]["urls"].append(url)
            if not all_services[service]["description"]:
                all_services[service]["description"] = f"{service} reported Java deserialization behavior"

        for service, data in all_services.items():
            if not data["urls"]:
                continue  # Только уязвимые
            checks = [
                f"{proto}: [{', '.join(map(str, sorted(ports)))}]"
                for proto, ports in data["proto_ports"].items()
            ]
            final[service] = {
                "urls": data["urls"],
                "description": data["description"],
                "checks": checks
            }

    elif has_not_vuln:
        final["status"] = "Not Vulnerable"
        for service, data in all_services.items():
            checks = [
                f"{proto}: [{', '.join(map(str, sorted(ports)))}]"
                for proto, ports in data["proto_ports"].items()
            ]
            final[service] = {
                "checks": checks
            }

    elif has_conn_err:
        final["status"] = "Connection error"
        for service, data in all_services.items():
            checks = [
                f"{proto}: [{', '.join(map(str, sorted(ports)))}]"
                for proto, ports in data["proto_ports"].items()
            ]
            final[service] = {
                "checks": checks
            }

    return final
