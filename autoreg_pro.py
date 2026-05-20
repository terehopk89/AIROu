"""
Owner-side registration test client for xyecoc.com.

This script intentionally identifies itself as an internal test client. Keep it
that way when using it to verify server-side bot and rate-limit defenses.
"""
from __future__ import annotations

import asyncio
import json
import logging
import secrets
import string
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import NamedTuple

import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

API_URL = "https://api.xyecoc.com/request"
DOMAIN = "@dev-play.space"
TIMEOUT = 12.0
MAX_RETRIES = 2
CONCURRENT_LIMIT = 5
MIN_PASSWORD_LENGTH = 8
CLIENT_USER_AGENT = "XYECOC-Owner-Registration-Test/1.0"
BLOCKED_MARKERS = ("ip", "blocked", "too many", "many requests", "rate limit", "много")


class RegResult(NamedTuple):
    success: bool
    account: Account | None
    error: str
    proxy: str | None


@dataclass(slots=True)
class Account:
    email: str
    password: str
    proxy: str | None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass(slots=True)
class ProxyState:
    url: str
    success: int = 0
    fails: int = 0
    blocked: bool = False

    @property
    def is_available(self) -> bool:
        return not self.blocked and self.fails < 5


def gen_email() -> str:
    """Generate a random local-part accepted by the current frontend rules."""
    length = secrets.randbelow(3) + 10
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def gen_password(length: int = 16) -> str:
    """Generate a password matching the current frontend validation rules."""
    length = max(length, MIN_PASSWORD_LENGTH)
    alphabet = string.ascii_letters + string.digits
    chars = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
    ]
    chars.extend(secrets.choice(alphabet) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def get_headers() -> dict[str, str]:
    """Return explicit owner-test headers instead of browser impersonation."""
    return {
        "Content-Type": "application/json;charset=utf-8",
        "Accept": "application/json, text/plain, */*",
        "Origin": "https://xyecoc.com",
        "Referer": "https://xyecoc.com/",
        "User-Agent": CLIENT_USER_AGENT,
        "X-Audit-Client": "xyecoc-owner-registration-test",
    }


def is_blocked_message(message: str) -> bool:
    lowered = message.lower()
    return any(marker in lowered for marker in BLOCKED_MARKERS)


async def post_api(
    client: httpx.AsyncClient,
    api_url: str,
    action: str,
    data: dict[str, str],
) -> tuple[int, dict]:
    response = await client.post(
        api_url,
        json={"service": "account", "action": action, "data": data},
        headers=get_headers(),
    )
    if response.status_code != 200:
        return response.status_code, {}
    try:
        return response.status_code, response.json()
    except ValueError:
        return response.status_code, {"status": 0, "message": "invalid json response"}


async def register_account(
    client: httpx.AsyncClient,
    proxy: str | None,
    *,
    api_url: str = API_URL,
    domain: str = DOMAIN,
) -> RegResult:
    """Register one account against an owner-controlled environment."""
    for _attempt in range(MAX_RETRIES + 1):
        username = gen_email()
        password = gen_password()

        try:
            check_status, check_data = await post_api(
                client,
                api_url,
                "check-mailbox",
                {"email": username},
            )
            if check_status != 200:
                continue

            if check_data.get("status") == 0:
                message = str(check_data.get("message", ""))
                if is_blocked_message(message):
                    return RegResult(False, None, "IP_BLOCKED", proxy)
                continue

            if check_data.get("status") != 1:
                continue

            reg_status, reg_data = await post_api(
                client,
                api_url,
                "register",
                {"email": username, "password": password, "password_repeat": password},
            )
            if reg_status != 200:
                continue

            if reg_data.get("status") == 1:
                account = Account(email=f"{username}{domain}", password=password, proxy=proxy)
                return RegResult(True, account, "OK", proxy)

            message = str(reg_data.get("message", ""))
            if is_blocked_message(message):
                return RegResult(False, None, "IP_BLOCKED", proxy)

            return RegResult(False, None, f"REG_FAIL: {message}", proxy)

        except httpx.TimeoutException:
            continue
        except httpx.ProxyError:
            return RegResult(False, None, "PROXY_ERROR", proxy)
        except httpx.TransportError as exc:
            return RegResult(False, None, f"TRANSPORT_ERROR: {type(exc).__name__}", proxy)

    return RegResult(False, None, "MAX_RETRIES", proxy)


async def worker(
    proxy_state: ProxyState,
    results: list[Account],
    stats: dict[str, int],
    semaphore: asyncio.Semaphore,
    lock: asyncio.Lock,
    *,
    target: int,
    api_url: str,
    domain: str,
    verify_tls: bool,
) -> None:
    """Run one registration attempt for a proxy."""
    async with semaphore:
        async with lock:
            if len(results) >= target or not proxy_state.is_available:
                return

        timeout = httpx.Timeout(TIMEOUT, connect=10.0, read=TIMEOUT, write=TIMEOUT, pool=5.0)
        limits = httpx.Limits(max_connections=5, max_keepalive_connections=2)
        client_kwargs = {
            "verify": verify_tls,
            "timeout": timeout,
            "limits": limits,
        }
        if proxy_state.url:
            client_kwargs["proxy"] = proxy_state.url

        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                result = await register_account(
                    client,
                    proxy_state.url,
                    api_url=api_url,
                    domain=domain,
                )
        except Exception as exc:
            result = RegResult(False, None, f"ERROR: {type(exc).__name__}", proxy_state.url)

        async with lock:
            if result.success and result.account:
                if len(results) >= target:
                    return
                results.append(result.account)
                proxy_state.success += 1
                stats["success"] += 1
                logger.info("Registered %s via %s", result.account.email, proxy_state.url)
            elif result.error == "IP_BLOCKED":
                proxy_state.blocked = True
                stats["blocked"] += 1
                logger.warning("Blocked by API via %s", proxy_state.url)
            elif result.error == "TIMEOUT":
                proxy_state.fails += 1
                stats["timeout"] += 1
            else:
                proxy_state.fails += 1
                stats["failed"] += 1


async def run_registration(
    proxies: list[str],
    target: int,
    output: Path,
    *,
    concurrent: int = CONCURRENT_LIMIT,
    api_url: str = API_URL,
    domain: str = DOMAIN,
    verify_tls: bool = True,
) -> None:
    """Main registration loop."""
    stats = {"success": 0, "failed": 0, "blocked": 0, "timeout": 0}
    results: list[Account] = []

    if target < 1:
        raise ValueError("target must be at least 1")

    if not proxies:
        stats["failed"] = target
        logger.error("No proxies provided; refusing to run network registration attempts.")
        save_results(results, stats, output, target)
        return

    proxy_states = [ProxyState(url=p) for p in proxies]
    concurrent = max(1, min(concurrent, len(proxy_states), target))
    semaphore = asyncio.Semaphore(concurrent)
    lock = asyncio.Lock()
    rounds = 0
    max_rounds = max(1, (target * (MAX_RETRIES + 1) + len(proxy_states) - 1) // len(proxy_states))

    logger.info("=" * 50)
    logger.info("Owner registration test client")
    logger.info("Target: %s", target)
    logger.info("Proxies: %s", len(proxies))
    logger.info("Concurrent: %s", concurrent)
    logger.info("API: %s", api_url)
    logger.info("Domain: %s", domain)
    logger.info("TLS verify: %s", verify_tls)
    logger.info("=" * 50)

    while len(results) < target and rounds < max_rounds:
        rounds += 1
        available = [p for p in proxy_states if p.is_available]
        if not available:
            logger.error("No available proxies remain.")
            break

        remaining = target - len(results)
        batch = available[: min(len(available), remaining, concurrent)]
        tasks = [
            worker(
                proxy_state,
                results,
                stats,
                semaphore,
                lock,
                target=target,
                api_url=api_url,
                domain=domain,
                verify_tls=verify_tls,
            )
            for proxy_state in batch
        ]
        await asyncio.gather(*tasks)
        logger.info(
            "Round %s: %s/%s | success=%s blocked=%s timeout=%s failed=%s",
            rounds,
            len(results),
            target,
            stats["success"],
            stats["blocked"],
            stats["timeout"],
            stats["failed"],
        )

    save_results(results, stats, output, target)


def save_results(results: list[Account], stats: dict[str, int], output: Path, target: int) -> None:
    """Save JSON results and the legacy email:password list."""
    output.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "accounts": [
            {"email": a.email, "password": a.password, "proxy": a.proxy, "created_at": a.created_at}
            for a in results
        ],
        "stats": stats,
        "target": target,
        "timestamp": datetime.now().isoformat(),
    }

    output.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    with open("all.txt", "a", encoding="utf-8") as f:
        for account in results:
            f.write(f"{account.email}:{account.password}\n")

    logger.info("=" * 50)
    logger.info("Registered: %s/%s", stats["success"], target)
    logger.info("Blocked: %s", stats["blocked"])
    logger.info("Timeout: %s", stats["timeout"])
    logger.info("Failed: %s", stats["failed"])
    logger.info("Saved: %s and all.txt", output)


def load_proxies(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="XYECOC owner registration test client")
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--proxy-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("accounts_pro.json"))
    parser.add_argument("--concurrent", type=int, default=CONCURRENT_LIMIT)
    parser.add_argument("--api-url", default=API_URL)
    parser.add_argument("--domain", default=DOMAIN)
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification for lab proxies only")

    args = parser.parse_args()

    try:
        proxies = load_proxies(args.proxy_file)
    except FileNotFoundError:
        logger.error("Proxy file not found: %s", args.proxy_file)
        sys.exit(1)

    if not proxies:
        logger.error("No proxies found in %s", args.proxy_file)
        sys.exit(1)

    asyncio.run(
        run_registration(
            proxies,
            args.count,
            args.output,
            concurrent=args.concurrent,
            api_url=args.api_url,
            domain=args.domain,
            verify_tls=not args.insecure,
        )
    )


if __name__ == "__main__":
    main()
