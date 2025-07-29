#!/usr/bin/env python3
import argparse
import json
import pathlib
import threading
from collections import defaultdict
from typing import Any, Final
from urllib.parse import urlparse

from attacks.java_deser import (
    full_check_websphere,
    full_check_weblogic,
    full_check_jboss,
    full_check_jenkins,
)
from attacks.serialator_deser import (
    full_check_symantec,
    full_check_opennms,
)
from attacks.sort_res import merge_results_from_file

SERVICES = {
    "websphere": {
        "func": full_check_websphere,
        "ports": [8880, 9443, 9060, 9043, 9080],
        "protocols": ["https", "http"],
        "details": "WebSphere endpoint responded with Java serialized data marker (rO0AB)",
    },
    "weblogic": {
        "func": full_check_weblogic,
        "ports": [7001, 7002, 8001],
        "protocols": ["t3"],
        "details": "WebLogic T3 service accepted handshake, indicating potential Java deserialization",
    },
    "jboss": {
        "func": full_check_jboss,
        "ports": [8080, 8180, 80, 443],
        "protocols": ["https", "http"],
        "details": "JBoss JMXInvokerServlet accepted serialized payload and returned HTTP 200",
    },
    "jenkins": {
        "func": full_check_jenkins,
        "ports": [8080],
        "protocols": ["https", "http"],
        "details": "Jenkins CLI port responded with serialized data marker (rO0AB)",
    },
    "symantec": {
        "func": full_check_symantec,
        "ports": [8443, 8080],
        "protocols": ["https", "http"],
        "details": "Symantec EP Manager endpoint accepted Java serialized object via multipart POST",
    },
    "opennms": {
        "func": full_check_opennms,
        "ports": [1099, 1100, 8980],
        "protocols": ["rmi"],
        "details": "OpenNMS RMI service responded to JRMI banner and second-stage payload",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Unified Java Deserialization Scanner")

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument("--target", help="Single host to scan (FQDN or IP)")
    group.add_argument("--file", help="File with hosts, one per line")

    parser.add_argument("--output", required=True, help="Path to JSON output file")
    parser.add_argument("--threads", type=int, default=30, help="Max concurrent threads")
    parser.add_argument("--icmp-listen", action="store_true", help="Enable ICMPListener for RCE proof")

    return parser.parse_args()


def worker(host: str, results: list[dict[str, Any]]):
    for name, cfg in SERVICES.items():
        for port in cfg["ports"]:
            for proto in cfg["protocols"]:
                try:
                    res = cfg["func"](host, port, proto)
                except Exception as e:
                    res = {"service": name, "url": f"{proto}://{host}:{port}", "status": "Error", "error": str(e)}
                results.append(res)


def main():
    args = parse_args()

    workers: int = args.threads

    MAIN_DIR: Final[pathlib.Path] = pathlib.Path(__file__).resolve().parents[0]

    output_file = MAIN_DIR / args.output

    if args.target:
        target: str = args.target
        hosts = [target]
    elif args.file:
        input_file = MAIN_DIR / args.file
        with open(input_file) as f:
            hosts = [line.strip() for line in f if line.strip()]
    else:
        raise Exception("No target specified")

    results: list[dict[str, Any]] = []
    threads: list[threading.Thread] = []

    for host in hosts:
        t = threading.Thread(target=worker, args=(host, results))
        t.start()
        threads.append(t)
        while threading.active_count() > workers:
            pass

    for t in threads:
        t.join()

    results_dict = merge_results_from_file(results, args.target)

    with open(output_file, "w") as jf:
        json.dump(results_dict, jf, indent=2)


if __name__ == "__main__":
    main()
