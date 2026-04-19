#!/usr/bin/env python3
"""
check_block.py — TCP + TLS + CERT + HTTP connectivity checker.

Проверяет четыре уровня доступности сервиса за одно TCP-соединение:
  1. TCP  — устанавливается ли соединение
  2. TLS  — проходит ли handshake с заданным SNI
  3. CERT — совпадение CN/SAN с SNI и срок действия
  4. HTTP — HTTP-ответ через тот же TLS-сокет

Полезно для диагностики блокировок ТСПУ, REALITY-нод, маскирующих прокси и т.д.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import socket
import ssl
import sys
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


DEFAULT_TIMEOUT = 5.0
USER_AGENT = "curl/8.0"


# ─────────────────────────── result types ───────────────────────────

class Status(Enum):
    OK      = "OK"
    FAIL    = "FAIL"
    TIMEOUT = "TIMEOUT"
    REFUSED = "REFUSED"
    RST     = "RST"
    SKIP    = "SKIP"


@dataclass
class StepResult:
    name: str
    status: Status
    elapsed: float = 0.0
    message: str = ""
    details: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status is Status.OK


# ─────────────────────────── checks ───────────────────────────

def check_tcp(ip: str, port: int, timeout: float
              ) -> tuple[StepResult, Optional[socket.socket]]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start = time.monotonic()
    try:
        sock.connect((ip, port))
    except socket.timeout:
        sock.close()
        return StepResult("TCP", Status.TIMEOUT, time.monotonic() - start,
                          "drop/firewall"), None
    except ConnectionRefusedError:
        sock.close()
        return StepResult("TCP", Status.REFUSED, time.monotonic() - start,
                          "порт закрыт"), None
    except OSError as e:
        sock.close()
        return StepResult("TCP", Status.FAIL, time.monotonic() - start, str(e)), None

    return StepResult("TCP", Status.OK, time.monotonic() - start), sock


def check_tls(sock: socket.socket, sni: str, timeout: float
              ) -> tuple[StepResult, Optional[ssl.SSLSocket]]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    start = time.monotonic()
    try:
        tls_sock = ctx.wrap_socket(sock, server_hostname=sni,
                                   do_handshake_on_connect=False)
        tls_sock.settimeout(timeout)
        tls_sock.do_handshake()
    except socket.timeout:
        sock.close()
        return StepResult("TLS", Status.TIMEOUT, time.monotonic() - start,
                          "DPI по fingerprint/SNI?"), None
    except ConnectionResetError:
        sock.close()
        return StepResult("TLS", Status.RST, time.monotonic() - start,
                          "активная блокировка"), None
    except ssl.SSLError as e:
        sock.close()
        return StepResult("TLS", Status.FAIL, time.monotonic() - start,
                          f"ssl error: {e.reason}"), None
    except OSError as e:
        sock.close()
        return StepResult("TLS", Status.FAIL, time.monotonic() - start, str(e)), None

    return StepResult("TLS", Status.OK, time.monotonic() - start,
                      details={"version": tls_sock.version(),
                               "cipher":  tls_sock.cipher()[0]}), tls_sock


def _parse_peer_cert(tls_sock: ssl.SSLSocket) -> Optional[dict]:
    """Парсит peer cert, полученный в handshake при CERT_NONE.

    getpeercert() с CERT_NONE возвращает пустой dict, поэтому используется
    ssl._ssl._test_decode_cert — недокументированная, но стабильная за много
    лет функция (ею пользуется сам модуль ssl в своих тестах). Это единственный
    способ без сторонних зависимостей.
    """
    der = tls_sock.getpeercert(binary_form=True)
    if not der:
        return None

    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(pem)
        path = f.name
    try:
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
    finally:
        os.unlink(path)


def _sni_matches(name: str, pattern: str) -> bool:
    """Сравнение имени с паттерном из сертификата (RFC 6125).

    Wildcard матчит ровно один уровень:
      *.example.com → a.example.com  ✓
      *.example.com → a.b.example.com ✗
    """
    name = name.lower()
    pattern = pattern.lower()
    if pattern.startswith("*."):
        suffix = pattern[2:]
        head, _, tail = name.partition(".")
        return bool(head) and tail == suffix
    return name == pattern


def check_cert(tls_sock: ssl.SSLSocket, sni: str) -> StepResult:
    start = time.monotonic()
    try:
        parsed = _parse_peer_cert(tls_sock)
    except Exception as e:
        return StepResult("CERT", Status.FAIL, time.monotonic() - start,
                          f"не удалось распарсить: {e}")
    if parsed is None:
        return StepResult("CERT", Status.FAIL, time.monotonic() - start,
                          "сервер не прислал сертификат")

    subject = dict(x[0] for x in parsed.get("subject", ()))
    cn = subject.get("commonName", "")
    sans = [v for t, v in parsed.get("subjectAltName", ()) if t == "DNS"]

    not_after_str = parsed.get("notAfter", "")
    try:
        # OpenSSL-формат: "Jun 19 07:20:17 2026 GMT"
        not_after = dt.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        not_after = not_after.replace(tzinfo=dt.timezone.utc)
        now = dt.datetime.now(dt.timezone.utc)
        expired = now > not_after
        days_left = (not_after - now).days
    except ValueError:
        expired = False
        days_left = None

    sni_matched = any(_sni_matches(sni, s) for s in sans) \
                  or _sni_matches(sni, cn)

    ok = sni_matched and not expired
    return StepResult(
        "CERT", Status.OK if ok else Status.FAIL, time.monotonic() - start,
        details={
            "cn": cn, "sans": sans, "not_after": not_after_str,
            "days_left": days_left, "expired": expired,
            "sni_matched": sni_matched,
        },
    )


def check_http(tls_sock: ssl.SSLSocket, host_header: str, timeout: float
               ) -> StepResult:
    """Шлёт сырой GET / в уже установленный TLS-сокет и читает status line."""
    request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        f"Connection: close\r\n"
        f"Accept: */*\r\n"
        f"\r\n"
    ).encode()

    start = time.monotonic()
    tls_sock.settimeout(timeout)
    try:
        tls_sock.sendall(request)
        buf = b""
        while b"\r\n" not in buf and len(buf) < 4096:
            chunk = tls_sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        return StepResult("HTTP", Status.TIMEOUT, time.monotonic() - start)
    except ConnectionResetError:
        return StepResult("HTTP", Status.RST, time.monotonic() - start,
                          "активная блокировка")
    except OSError as e:
        return StepResult("HTTP", Status.FAIL, time.monotonic() - start, str(e))

    elapsed = time.monotonic() - start
    status_line = buf.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
    if not status_line.startswith("HTTP/"):
        return StepResult("HTTP", Status.FAIL, elapsed,
                          f"не HTTP-ответ: {status_line[:60]!r}")
    return StepResult("HTTP", Status.OK, elapsed, status_line)


# ─────────────────────────── output ───────────────────────────

_USE_COLOR = sys.stdout.isatty()
_COLORS = {"green": "32", "red": "31", "yellow": "33"}


def _c(text: str, color: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{_COLORS[color]}m{text}\033[0m"


_STATUS_STYLE = {
    Status.OK:      ("green",  "✓"),
    Status.FAIL:    ("red",    "✗"),
    Status.TIMEOUT: ("red",    "✗"),
    Status.REFUSED: ("red",    "✗"),
    Status.RST:     ("red",    "✗"),
    Status.SKIP:    ("yellow", "⚠"),
}


def _fmt_row(step: StepResult) -> str:
    color, mark = _STATUS_STYLE[step.status]
    head = f"{step.name:<5} {step.status.value:<8}"
    timing = f"({step.elapsed * 1000:.0f} ms)" if step.elapsed else ""
    msg = f" — {step.message}" if step.message else ""
    return f"{_c(mark, color)}  {head} {timing}{msg}".rstrip()


def _print_details(step: StepResult, sni: str) -> None:
    d = step.details
    if step.name == "TLS":
        print(f"       version : {d['version']}")
        print(f"       cipher  : {d['cipher']}")
    elif step.name == "CERT":
        print(f"       CN      : {d['cn'] or '—'}")
        print(f"       SANs    : {', '.join(d['sans']) or '—'}")
        mark = _c("✓", "green") if d["sni_matched"] else _c("✗", "red")
        print(f"       SNI     : {mark} {sni}")
        exp_mark = _c("✗ истёк", "red") if d["expired"] else _c("✓", "green")
        expiry = d["not_after"]
        if d["days_left"] is not None:
            expiry += f"  ({d['days_left']}д)"
        print(f"       expires : {exp_mark} {expiry}")


# ─────────────────────────── orchestrator ───────────────────────────

def run(ip: str, port: int, sni: Optional[str], timeout: float) -> int:
    """Выполняет все проверки последовательно. Возвращает exit code."""
    display_sni = sni or ip
    note = "" if sni else "  (не задан, проверка сертификата пропущена)"

    print(f"\nTarget : {ip}:{port}")
    print(f"SNI    : {display_sni}{note}")
    print("-" * 44)

    had_failure = False

    # TCP
    tcp_res, raw_sock = check_tcp(ip, port, timeout)
    print(_fmt_row(tcp_res))
    if not tcp_res.ok:
        print("-" * 44)
        return 2

    # TLS
    tls_res, tls_sock = check_tls(raw_sock, display_sni, timeout)
    print(_fmt_row(tls_res))
    if not tls_res.ok:
        print("-" * 44)
        return 2
    _print_details(tls_res, display_sni)

    # CERT
    if sni:
        cert_res = check_cert(tls_sock, sni)
        print(_fmt_row(cert_res))
        _print_details(cert_res, sni)
        had_failure |= not cert_res.ok
    else:
        print(_fmt_row(StepResult("CERT", Status.SKIP, 0.0, "SNI не задан")))

    # HTTP
    http_res = check_http(tls_sock, display_sni, timeout)
    print(_fmt_row(http_res))
    had_failure |= not http_res.ok

    try:
        tls_sock.close()
    except OSError:
        pass

    print("-" * 44)
    return 2 if had_failure else 0


# ─────────────────────────── CLI ───────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="check_block.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="TCP + TLS + CERT + HTTP checker для VPN нод и сервисов за ТСПУ.",
        epilog="""\
Examples:
  check_block.py 213.155.12.140 443
  check_block.py 213.155.12.140 8443 chksum.net
  check_block.py 89.125.48.193  2083 chksum.net
  check_block.py 217.177.34.139 443  rijksoverheid.nl --timeout 10

Exit codes:
  0 — все проверки прошли
  не 0 — одна из проверок упала или ошибка аргументов
""")
    p.add_argument("ip", help="IP адрес сервера")
    p.add_argument("port", type=int, help="TCP порт (1-65535)")
    p.add_argument("sni", nargs="?", default=None,
                   help="SNI домен (если не указан — проверка сертификата пропускается)")
    p.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT,
                   help=f"таймаут каждого шага в секундах (default: {DEFAULT_TIMEOUT})")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    if not (1 <= args.port <= 65535):
        print(f"error: port {args.port} вне диапазона 1-65535", file=sys.stderr)
        return 1
    return run(args.ip, args.port, args.sni, args.timeout)


if __name__ == "__main__":
    sys.exit(main())
