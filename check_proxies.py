"""Proxy checker for owner-side xyecoc.com registration defense testing."""
from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

API_URL = "https://api.xyecoc.com/request"
TIMEOUT = 15
DEFAULT_PROXY_FILES: tuple[tuple[Path, str], ...] = (
    (Path("proxy_http_ip.txt"), "http"),
    (Path("proxy_https_ip.txt"), "http"),
    (Path("proxy_socks_ip.txt"), "socks5"),
)


def normalize_proxy(proxy: str, default_scheme: str) -> str:
    proxy = proxy.strip()
    if "://" in proxy:
        return proxy
    return f"{default_scheme}://{proxy}"


def load_proxy_files(sources: list[tuple[Path, str]] | tuple[tuple[Path, str], ...]) -> list[str]:
    proxies: list[str] = []
    for path, default_scheme in sources:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            print(f"{path} not found")
            continue

        for line in lines:
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue
            proxies.append(normalize_proxy(clean, default_scheme))

    return proxies


def is_blocked_message(message: str) -> bool:
    lowered = message.lower()
    markers = ("ip", "blocked", "too many", "many requests", "rate limit", "много")
    return any(marker in lowered for marker in markers)


def check_proxy(proxy: str, *, verify_tls: bool = True) -> tuple[str, bool, str]:
    """Check whether a proxy can reach the registration API."""
    proxies_dict = {"http": proxy, "https": proxy}
    payload = {
        "service": "account",
        "action": "check-mailbox",
        "data": {"email": "testcheck123"},
    }
    headers = {
        "Content-Type": "application/json;charset=utf-8",
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "XYECOC-Owner-Proxy-Check/1.0",
        "X-Audit-Client": "xyecoc-owner-proxy-check",
    }

    try:
        resp = requests.post(
            API_URL,
            json=payload,
            headers=headers,
            proxies=proxies_dict,
            timeout=TIMEOUT,
            verify=verify_tls,
        )

        if resp.status_code != 200:
            return proxy, False, f"HTTP {resp.status_code}"

        try:
            data = resp.json()
        except ValueError:
            return proxy, False, "INVALID JSON"

        if data.get("status") == 1:
            return proxy, True, "OK - email not exists"

        message = str(data.get("message", ""))
        if is_blocked_message(message):
            return proxy, False, f"IP BLOCKED: {message}"

        return proxy, True, f"OK - {message}"

    except requests.Timeout:
        return proxy, False, "TIMEOUT"
    except requests.exceptions.ProxyError:
        return proxy, False, "PROXY ERROR"
    except requests.exceptions.SSLError:
        return proxy, False, "TLS ERROR"
    except requests.RequestException as exc:
        return proxy, False, f"REQUEST ERROR: {type(exc).__name__}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check proxies against the xyecoc.com owner test API")
    parser.add_argument("--proxy-file", action="append", type=Path, help="Proxy file; may be passed multiple times")
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument("--output", type=Path, default=Path("proxies_checked.txt"))
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification for lab proxies only")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.proxy_file:
        sources = [(path, "http") for path in args.proxy_file]
    else:
        sources = DEFAULT_PROXY_FILES

    all_proxies = load_proxy_files(sources)
    print(f"\nTotal proxies to check: {len(all_proxies)}")
    print(f"Workers: {args.workers}")
    print("=" * 60)

    if not all_proxies:
        print("No proxies found")
        sys.exit(1)

    working: list[str] = []
    blocked: list[str] = []
    failed: list[str] = []
    verify_tls = not args.insecure

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {executor.submit(check_proxy, proxy, verify_tls=verify_tls): proxy for proxy in all_proxies}

        for i, future in enumerate(as_completed(futures), 1):
            proxy, is_working, message = future.result()

            if is_working:
                working.append(proxy)
                print(f"OK [{i}/{len(all_proxies)}] {proxy} - {message}")
            elif "BLOCKED" in message:
                blocked.append(proxy)
                print(f"BLOCKED [{i}/{len(all_proxies)}] {proxy} - {message}")
            else:
                failed.append(proxy)
                print(f"FAIL [{i}/{len(all_proxies)}] {proxy} - {message}")

    print("=" * 60)
    print("RESULTS:")
    print(f"  Working: {len(working)}")
    print(f"  IP blocked: {len(blocked)}")
    print(f"  Failed: {len(failed)}")

    if working:
        args.output.write_text(
            "# Working proxies checked against xyecoc.com owner test API\n"
            + "\n".join(working)
            + "\n",
            encoding="utf-8",
        )
        print(f"Working proxies saved to {args.output}")
    else:
        print("No working proxies found")


if __name__ == "__main__":
    main()
