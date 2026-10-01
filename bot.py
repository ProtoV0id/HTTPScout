import asyncio
import ipaddress
import logging
import os
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse

import aiohttp
import discord
from aiohttp.abc import AbstractResolver
from discord import app_commands
from dotenv import load_dotenv


# =========================================================
# Configuration
# =========================================================

load_dotenv()

TOKEN = os.getenv("DISCORD_TOKEN")
GUILD_ID = os.getenv("GUILD_ID")

if not TOKEN:
    raise RuntimeError(
        "DISCORD_TOKEN is not set in .env"
    )

if not GUILD_ID:
    raise RuntimeError(
        "GUILD_ID is not set in .env"
    )

GUILD_ID = int(GUILD_ID)


# =========================================================
# Safety Configuration
# =========================================================

MAX_REDIRECTS = 5

MAX_URL_LENGTH = 2048

REQUEST_TIMEOUT = 10

MAX_CONCURRENT_REQUESTS = 4

MAX_BULK_URLS = 10

ALLOWED_PORTS = {
    80,
    443
}

USER_RATE_LIMIT = 5

USER_RATE_PERIOD = 30.0


HTTP_SEMAPHORE = asyncio.Semaphore(
    MAX_CONCURRENT_REQUESTS
)


# =========================================================
# Logging Configuration
# =========================================================

LOG_DIRECTORY = Path("logs")

LOG_DIRECTORY.mkdir(
    exist_ok=True
)

LOG_FILE = (
    LOG_DIRECTORY
    / "httpscout.log"
)

logger = logging.getLogger(
    "HTTPScout"
)

logger.setLevel(
    logging.INFO
)

log_formatter = logging.Formatter(
    (
        "%(asctime)s | "
        "%(levelname)s | "
        "%(message)s"
    )
)

file_handler = logging.FileHandler(
    LOG_FILE,
    encoding="utf-8"
)

file_handler.setFormatter(
    log_formatter
)

console_handler = logging.StreamHandler()

console_handler.setFormatter(
    log_formatter
)

logger.addHandler(
    file_handler
)

logger.addHandler(
    console_handler
)


# =========================================================
# Logging Helpers
# =========================================================

def sanitize_for_log(value: str) -> str:
    """
    Remove URL query strings and fragments before
    writing targets to the audit log.
    """

    try:
        normalized = normalize_url(
            value
        )

        parsed = urlparse(
            normalized
        )

        sanitized = parsed._replace(
            query="",
            fragment=""
        )

        return urlunparse(
            sanitized
        )

    except Exception:
        return "<invalid-target>"


def log_command(
    interaction: discord.Interaction,
    command: str,
    target: str = ""
):
    """
    Write basic command usage information.

    We log numeric Discord IDs rather than usernames
    so name changes don't make the audit trail useless.
    """

    safe_target = (
        sanitize_for_log(target)
        if target
        else "-"
    )

    logger.info(
        (
            "COMMAND "
            "command=%s "
            "user_id=%s "
            "guild_id=%s "
            "target=%s"
        ),
        command,
        interaction.user.id,
        interaction.guild_id,
        safe_target
    )


def log_result(
    command: str,
    target: str,
    status=None,
    elapsed=None
):
    safe_target = sanitize_for_log(
        target
    )

    logger.info(
        (
            "RESULT "
            "command=%s "
            "target=%s "
            "status=%s "
            "elapsed_ms=%s"
        ),
        command,
        safe_target,
        status,
        elapsed
    )


def log_failure(
    command: str,
    target: str,
    error
):
    safe_target = sanitize_for_log(
        target
    )

    logger.warning(
        (
            "FAILURE "
            "command=%s "
            "target=%s "
            "error=%s"
        ),
        command,
        safe_target,
        type(error).__name__
    )


# =========================================================
# Discord Client
# =========================================================

class HTTPScoutClient(discord.Client):

    def __init__(self):
        intents = discord.Intents.default()

        super().__init__(
            intents=intents
        )

        self.tree = app_commands.CommandTree(
            self
        )

    async def setup_hook(self):
        guild = discord.Object(
            id=GUILD_ID
        )

        self.tree.copy_global_to(
            guild=guild
        )

        synced = await self.tree.sync(
            guild=guild
        )

        logger.info(
            (
                "Synced %s command(s) "
                "to guild %s"
            ),
            len(synced),
            GUILD_ID
        )


client = HTTPScoutClient()


# =========================================================
# IP Safety Checks
# =========================================================

def is_safe_ip(ip_string: str) -> bool:
    """
    Only allow publicly routable addresses.
    """

    try:
        ip = ipaddress.ip_address(
            ip_string
        )

    except ValueError:
        return False

    if ip.is_private:
        return False

    if ip.is_loopback:
        return False

    if ip.is_link_local:
        return False

    if ip.is_multicast:
        return False

    if ip.is_reserved:
        return False

    if ip.is_unspecified:
        return False

    return True


# =========================================================
# Safe DNS Resolver
# =========================================================

class SafeResolver(AbstractResolver):

    async def resolve(
        self,
        host,
        port=0,
        family=socket.AF_UNSPEC
    ):
        loop = asyncio.get_running_loop()

        results = await loop.getaddrinfo(
            host,
            port,
            type=socket.SOCK_STREAM,
            family=family
        )

        resolved = []

        seen = set()

        for (
            address_family,
            socktype,
            proto,
            canonname,
            sockaddr
        ) in results:

            ip_address = sockaddr[0]

            if ip_address in seen:
                continue

            seen.add(
                ip_address
            )

            if not is_safe_ip(
                ip_address
            ):
                raise ValueError(
                    (
                        "Target resolves to a "
                        "non-public IP address"
                    )
                )

            resolved.append(
                {
                    "hostname": host,
                    "host": ip_address,
                    "port": port,
                    "family": address_family,
                    "proto": proto,
                    "flags": socket.AI_NUMERICHOST
                }
            )

        if not resolved:
            raise ValueError(
                "Hostname did not resolve"
            )

        return resolved

    async def close(self):
        pass


# =========================================================
# URL Helpers
# =========================================================

def normalize_url(url: str) -> str:
    url = url.strip()

    parsed = urlparse(
        url
    )

    if not parsed.scheme:
        url = "https://" + url

    return url


def validate_url(url: str) -> str:
    """
    Validate a URL before HTTPScout requests it.
    """

    url = normalize_url(
        url
    )

    if len(url) > MAX_URL_LENGTH:
        raise ValueError(
            "URL is too long"
        )

    parsed = urlparse(
        url
    )

    if parsed.scheme not in {
        "http",
        "https"
    }:
        raise ValueError(
            (
                "Only http:// and https:// "
                "URLs are allowed"
            )
        )

    if not parsed.hostname:
        raise ValueError(
            "URL does not contain a hostname"
        )

    hostname = parsed.hostname.lower()

    blocked_names = {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal"
    }

    if hostname in blocked_names:
        raise ValueError(
            "Local/internal hosts are blocked"
        )

    if hostname.endswith(
        ".local"
    ):
        raise ValueError(
            "Local network hosts are blocked"
        )

    # -----------------------------------------------------
    # Literal IP Validation
    # -----------------------------------------------------

    literal_ip = None

    try:
        literal_ip = ipaddress.ip_address(
            hostname
        )

    except ValueError:
        pass

    if literal_ip is not None:

        if not is_safe_ip(
            str(literal_ip)
        ):
            raise ValueError(
                (
                    "Private, local, link-local, "
                    "or reserved IP addresses are blocked"
                )
            )

    # -----------------------------------------------------
    # Credentials
    # -----------------------------------------------------

    if parsed.username or parsed.password:
        raise ValueError(
            (
                "URLs containing usernames or "
                "passwords are not allowed"
            )
        )

    # -----------------------------------------------------
    # Port
    # -----------------------------------------------------

    try:
        port = parsed.port

    except ValueError:
        raise ValueError(
            "Invalid port"
        )

    if port is not None:

        if port not in ALLOWED_PORTS:
            raise ValueError(
                (
                    "Only ports 80 and 443 "
                    "are allowed"
                )
            )

    return url


# =========================================================
# DNS Helpers
# =========================================================

async def resolve_public_ips(
    hostname: str,
    port: int = 443
):
    hostname = hostname.strip().lower()

    if hostname in {
        "localhost",
        "localhost.localdomain"
    }:
        raise ValueError(
            "Local/internal hosts are blocked"
        )

    loop = asyncio.get_running_loop()

    results = await loop.getaddrinfo(
        hostname,
        port,
        type=socket.SOCK_STREAM
    )

    ipv4 = []
    ipv6 = []

    seen = set()

    for (
        family,
        socktype,
        proto,
        canonname,
        sockaddr
    ) in results:

        ip_address = sockaddr[0]

        if ip_address in seen:
            continue

        seen.add(
            ip_address
        )

        if not is_safe_ip(
            ip_address
        ):
            raise ValueError(
                (
                    "Target resolves to a "
                    "non-public IP address"
                )
            )

        if family == socket.AF_INET:
            ipv4.append(
                ip_address
            )

        elif family == socket.AF_INET6:
            ipv6.append(
                ip_address
            )

    if not ipv4 and not ipv6:
        raise ValueError(
            (
                "Hostname did not resolve "
                "to a public IP"
            )
        )

    return {
        "hostname": hostname,
        "ipv4": ipv4,
        "ipv6": ipv6
    }


# =========================================================
# TLS Helpers
# =========================================================

def flatten_certificate_name(name):
    parts = []

    for group in name:
        for key, value in group:
            parts.append(
                f"{key}={value}"
            )

    return ", ".join(
        parts
    )


async def inspect_tls(url: str):
    url = validate_url(
        url
    )

    parsed = urlparse(
        url
    )

    hostname = parsed.hostname

    if not hostname:
        raise ValueError(
            "URL does not contain a hostname"
        )

    dns_result = await resolve_public_ips(
        hostname,
        443
    )

    addresses = (
        dns_result["ipv4"]
        + dns_result["ipv6"]
    )

    context = ssl.create_default_context()

    last_error = None

    for target_ip in addresses:

        try:
            reader, writer = (
                await asyncio.wait_for(
                    asyncio.open_connection(
                        host=target_ip,
                        port=443,
                        ssl=context,
                        server_hostname=hostname
                    ),
                    timeout=REQUEST_TIMEOUT
                )
            )

            ssl_object = writer.get_extra_info(
                "ssl_object"
            )

            if ssl_object is None:
                raise RuntimeError(
                    "TLS connection was not established"
                )

            certificate = ssl_object.getpeercert()

            tls_version = ssl_object.version()

            cipher_info = ssl_object.cipher()

            cipher = (
                cipher_info[0]
                if cipher_info
                else "Unknown"
            )

            subject = flatten_certificate_name(
                certificate.get(
                    "subject",
                    ()
                )
            )

            issuer = flatten_certificate_name(
                certificate.get(
                    "issuer",
                    ()
                )
            )

            not_before_raw = certificate.get(
                "notBefore"
            )

            not_after_raw = certificate.get(
                "notAfter"
            )

            not_before = None
            not_after = None
            days_remaining = None

            if not_before_raw:
                timestamp = (
                    ssl.cert_time_to_seconds(
                        not_before_raw
                    )
                )

                not_before = datetime.fromtimestamp(
                    timestamp,
                    tz=timezone.utc
                )

            if not_after_raw:
                timestamp = (
                    ssl.cert_time_to_seconds(
                        not_after_raw
                    )
                )

                not_after = datetime.fromtimestamp(
                    timestamp,
                    tz=timezone.utc
                )

                days_remaining = (
                    not_after
                    - datetime.now(
                        timezone.utc
                    )
                ).days

            sans = []

            for (
                san_type,
                san_value
            ) in certificate.get(
                "subjectAltName",
                ()
            ):
                if san_type == "DNS":
                    sans.append(
                        san_value
                    )

            writer.close()

            await writer.wait_closed()

            return {
                "hostname": hostname,
                "ip": target_ip,
                "tls_version": tls_version,
                "cipher": cipher,
                "subject": subject or "Unknown",
                "issuer": issuer or "Unknown",
                "not_before": not_before,
                "not_after": not_after,
                "days_remaining": days_remaining,
                "sans": sans
            }

        except (
            OSError,
            ssl.SSLError,
            asyncio.TimeoutError
        ) as error:

            last_error = error

    raise RuntimeError(
        (
            "TLS connection failed"
            if last_error is None
            else
            (
                "TLS connection failed: "
                f"{type(last_error).__name__}"
            )
        )
    )


# =========================================================
# HTTP Request
# =========================================================

async def check_url(url: str):
    requested_url = validate_url(
        url
    )

    current_url = requested_url

    timeout = aiohttp.ClientTimeout(
        total=REQUEST_TIMEOUT
    )

    request_headers = {
        "User-Agent": "HTTPScout/1.0",
        "Accept": "*/*"
    }

    resolver = SafeResolver()

    connector = aiohttp.TCPConnector(
        resolver=resolver,
        limit=MAX_CONCURRENT_REQUESTS
    )

    redirects = []

    start = time.perf_counter()

    async with HTTP_SEMAPHORE:

        async with aiohttp.ClientSession(
            timeout=timeout,
            headers=request_headers,
            connector=connector
        ) as session:

            for redirect_number in range(
                MAX_REDIRECTS + 1
            ):

                current_url = validate_url(
                    current_url
                )

                async with session.get(
                    current_url,
                    allow_redirects=False
                ) as response:

                    status = response.status

                    response_headers = dict(
                        response.headers
                    )

                    if status in {
                        301,
                        302,
                        303,
                        307,
                        308
                    }:

                        location = (
                            response.headers.get(
                                "Location"
                            )
                        )

                        if not location:
                            break

                        if (
                            redirect_number
                            >= MAX_REDIRECTS
                        ):
                            raise ValueError(
                                (
                                    "Too many redirects "
                                    f"(maximum {MAX_REDIRECTS})"
                                )
                            )

                        next_url = urljoin(
                            current_url,
                            location
                        )

                        next_url = validate_url(
                            next_url
                        )

                        redirects.append(
                            {
                                "status": status,
                                "url": current_url,
                                "location": next_url
                            }
                        )

                        current_url = next_url

                        continue

                    elapsed_ms = round(
                        (
                            time.perf_counter()
                            - start
                        ) * 1000
                    )

                    return {
                        "requested_url": requested_url,
                        "status": status,
                        "final_url": str(
                            response.url
                        ),
                        "response_time": elapsed_ms,
                        "redirects": redirects,
                        "headers": response_headers
                    }

    raise RuntimeError(
        "Request ended unexpectedly"
    )


# =========================================================
# Status Helpers
# =========================================================

def get_status_style(status: int):

    if 200 <= status < 300:
        return (
            discord.Color.green(),
            "🟢"
        )

    if 300 <= status < 400:
        return (
            discord.Color.gold(),
            "🟡"
        )

    if 400 <= status < 500:
        return (
            discord.Color.orange(),
            "🟠"
        )

    return (
        discord.Color.red(),
        "🔴"
    )


# =========================================================
# Security Header Helpers
# =========================================================

def get_security_headers(headers: dict):

    normalized = {
        key.lower(): value
        for key, value
        in headers.items()
    }

    checks = [
        (
            "Strict-Transport-Security",
            "strict-transport-security"
        ),
        (
            "Content-Security-Policy",
            "content-security-policy"
        ),
        (
            "X-Content-Type-Options",
            "x-content-type-options"
        ),
        (
            "X-Frame-Options",
            "x-frame-options"
        ),
        (
            "Referrer-Policy",
            "referrer-policy"
        ),
        (
            "Permissions-Policy",
            "permissions-policy"
        )
    ]

    results = []

    for display_name, header_name in checks:

        value = normalized.get(
            header_name
        )

        results.append(
            {
                "name": display_name,
                "present": value is not None,
                "value": value
            }
        )

    return results


# =========================================================
# Shared Rate Limit
# =========================================================

rate_limit = app_commands.checks.cooldown(
    USER_RATE_LIMIT,
    USER_RATE_PERIOD,
    key=lambda interaction: (
        interaction.guild_id,
        interaction.user.id
    )
)


# =========================================================
# Events
# =========================================================

@client.event
async def on_ready():

    logger.info(
        "Logged in as %s",
        client.user
    )

    logger.info(
        "Bot ID: %s",
        client.user.id
    )


# =========================================================
# Command Error Handler
# =========================================================

@client.tree.error
async def on_app_command_error(
    interaction: discord.Interaction,
    error: app_commands.AppCommandError
):

    if isinstance(
        error,
        app_commands.CommandOnCooldown
    ):

        message = (
            "⏳ You're checking URLs too quickly. "
            f"Try again in {error.retry_after:.1f} seconds."
        )

    else:

        logger.exception(
            "Application command error",
            exc_info=error
        )

        message = (
            "❌ HTTPScout encountered an error."
        )

    if interaction.response.is_done():

        await interaction.followup.send(
            message,
            ephemeral=True
        )

    else:

        await interaction.response.send_message(
            message,
            ephemeral=True
        )


# =========================================================
# /status
# =========================================================

@client.tree.command(
    name="status",
    description="Check the HTTP status of a URL"
)
@app_commands.describe(
    url="Website or URL to check"
)
@rate_limit
async def status(
    interaction: discord.Interaction,
    url: str
):

    log_command(
        interaction,
        "status",
        url
    )

    await interaction.response.defer()

    try:
        result = await check_url(
            url
        )

        log_result(
            "status",
            url,
            result["status"],
            result["response_time"]
        )

        status_code = result["status"]

        color, status_icon = get_status_style(
            status_code
        )

        server = result["headers"].get(
            "Server",
            "Unknown"
        )

        content_type = result["headers"].get(
            "Content-Type",
            "Unknown"
        )

        content_length = result["headers"].get(
            "Content-Length",
            "Unknown"
        )

        embed = discord.Embed(
            title="🌐 HTTPScout",
            description=(
                "**HTTP analysis for**\n"
                f"{result['requested_url']}"
            ),
            color=color
        )

        embed.add_field(
            name="📡 Status",
            value=(
                "```"
                f"{status_icon} {status_code}"
                "```"
            ),
            inline=True
        )

        embed.add_field(
            name="⏱ Response Time",
            value=(
                "```"
                f"{result['response_time']} ms"
                "```"
            ),
            inline=True
        )

        embed.add_field(
            name="↪ Redirects",
            value=(
                "```"
                f"{len(result['redirects'])}"
                "```"
            ),
            inline=True
        )

        embed.add_field(
            name="🖥 Server",
            value=f"```{server}```",
            inline=True
        )

        embed.add_field(
            name="📄 Content Type",
            value=f"```{content_type}```",
            inline=True
        )

        embed.add_field(
            name="📦 Content Length",
            value=f"```{content_length}```",
            inline=True
        )

        embed.add_field(
            name="🔗 Final URL",
            value=(
                "```"
                f"{result['final_url']}"
                "```"
            ),
            inline=False
        )

        embed.set_footer(
            text=(
                "HTTPScout • "
                "Live HTTP analysis"
            )
        )

        await interaction.followup.send(
            embed=embed
        )

    except Exception as error:

        log_failure(
            "status",
            url,
            error
        )

        if isinstance(
            error,
            ValueError
        ):
            message = f"🚫 `{error}`"

        elif isinstance(
            error,
            asyncio.TimeoutError
        ):
            message = "⏱ Request timed out."

        else:
            message = "❌ Request failed."

        await interaction.followup.send(
            message
        )


# =========================================================
# /headers
# =========================================================

@client.tree.command(
    name="headers",
    description="Show HTTP response headers for a URL"
)
@app_commands.describe(
    url="Website or URL to check"
)
@rate_limit
async def headers(
    interaction: discord.Interaction,
    url: str
):

    log_command(
        interaction,
        "headers",
        url
    )

    await interaction.response.defer()

    try:
        result = await check_url(
            url
        )

        log_result(
            "headers",
            url,
            result["status"],
            result["response_time"]
        )

        header_text = ""

        for key, value in result[
            "headers"
        ].items():

            line = (
                f"{key}: {value}\n"
            )

            if (
                len(header_text)
                + len(line)
                > 950
            ):
                header_text += (
                    "\n...truncated"
                )

                break

            header_text += line

        color, status_icon = get_status_style(
            result["status"]
        )

        embed = discord.Embed(
            title="📋 HTTPScout Headers",
            description=result[
                "final_url"
            ],
            color=color
        )

        embed.add_field(
            name="📡 Status",
            value=(
                "```"
                f"{status_icon} "
                f"{result['status']}"
                "```"
            ),
            inline=True
        )

        embed.add_field(
            name="⏱ Response Time",
            value=(
                "```"
                f"{result['response_time']} ms"
                "```"
            ),
            inline=True
        )

        embed.add_field(
            name="📦 Header Count",
            value=(
                "```"
                f"{len(result['headers'])}"
                "```"
            ),
            inline=True
        )

        embed.add_field(
            name="Response Headers",
            value=(
                "```http\n"
                f"{header_text}"
                "\n```"
            ),
            inline=False
        )

        embed.set_footer(
            text="HTTPScout • Response headers"
        )

        await interaction.followup.send(
            embed=embed
        )

    except Exception as error:

        log_failure(
            "headers",
            url,
            error
        )

        await interaction.followup.send(
            f"❌ `{error}`"
        )


# =========================================================
# /redirects
# =========================================================

@client.tree.command(
    name="redirects",
    description="Show the redirect chain for a URL"
)
@app_commands.describe(
    url="Website or URL to inspect"
)
@rate_limit
async def redirects(
    interaction: discord.Interaction,
    url: str
):

    log_command(
        interaction,
        "redirects",
        url
    )

    await interaction.response.defer()

    try:
        result = await check_url(
            url
        )

        log_result(
            "redirects",
            url,
            result["status"],
            result["response_time"]
        )

        color, status_icon = get_status_style(
            result["status"]
        )

        embed = discord.Embed(
            title="🧭 HTTPScout Redirects",
            description=(
                "**Redirect analysis for**\n"
                f"{result['requested_url']}"
            ),
            color=color
        )

        embed.add_field(
            name="Redirect Count",
            value=(
                "```"
                f"{len(result['redirects'])}"
                "```"
            ),
            inline=True
        )

        embed.add_field(
            name="Final Status",
            value=(
                "```"
                f"{status_icon} {result['status']}"
                "```"
            ),
            inline=True
        )

        embed.add_field(
            name="Response Time",
            value=(
                "```"
                f"{result['response_time']} ms"
                "```"
            ),
            inline=True
        )

        if result["redirects"]:

            chain = ""

            for index, redirect in enumerate(
                result["redirects"],
                start=1
            ):

                chain += (
                    f"{index}. "
                    f"{redirect['status']}\n"
                    f"{redirect['url']}\n"
                    f"→ {redirect['location']}\n\n"
                )

            chain += (
                f"FINAL {result['status']}\n"
                f"{result['final_url']}"
            )

        else:

            chain = (
                "No redirects detected.\n\n"
                f"Final URL:\n"
                f"{result['final_url']}"
            )

        embed.add_field(
            name="Redirect Chain",
            value=(
                "```"
                f"{chain[:950]}"
                "```"
            ),
            inline=False
        )

        embed.set_footer(
            text=(
                "HTTPScout • "
                f"Maximum {MAX_REDIRECTS} redirects"
            )
        )

        await interaction.followup.send(
            embed=embed
        )

    except Exception as error:

        log_failure(
            "redirects",
            url,
            error
        )

        await interaction.followup.send(
            f"❌ `{error}`"
        )


# =========================================================
# /security
# =========================================================

@client.tree.command(
    name="security",
    description="Inspect common HTTP security headers"
)
@app_commands.describe(
    url="Website or URL to inspect"
)
@rate_limit
async def security(
    interaction: discord.Interaction,
    url: str
):

    log_command(
        interaction,
        "security",
        url
    )

    await interaction.response.defer()

    try:
        result = await check_url(
            url
        )

        checks = get_security_headers(
            result["headers"]
        )

        log_result(
            "security",
            url,
            result["status"],
            result["response_time"]
        )

        color, status_icon = get_status_style(
            result["status"]
        )

        embed = discord.Embed(
            title="🛡 HTTPScout Security",
            description=(
                "**Security header inspection for**\n"
                f"{result['final_url']}"
            ),
            color=color
        )

        embed.add_field(
            name="HTTP Status",
            value=(
                "```"
                f"{status_icon} {result['status']}"
                "```"
            ),
            inline=True
        )

        embed.add_field(
            name="Response Time",
            value=(
                "```"
                f"{result['response_time']} ms"
                "```"
            ),
            inline=True
        )

        embed.add_field(
            name="Redirects",
            value=(
                "```"
                f"{len(result['redirects'])}"
                "```"
            ),
            inline=True
        )

        for check_item in checks:

            if check_item["present"]:

                value = check_item[
                    "value"
                ]

                if len(value) > 200:
                    value = (
                        value[:197]
                        + "..."
                    )

                display = (
                    "```"
                    f"✅ {value}"
                    "```"
                )

            else:

                display = (
                    "```"
                    "❌ Missing"
                    "```"
                )

            embed.add_field(
                name=check_item["name"],
                value=display,
                inline=False
            )

        embed.set_footer(
            text=(
                "HTTPScout • "
                "Header presence is not a "
                "complete security assessment"
            )
        )

        await interaction.followup.send(
            embed=embed
        )

    except Exception as error:

        log_failure(
            "security",
            url,
            error
        )

        await interaction.followup.send(
            f"❌ `{error}`"
        )


# =========================================================
# /bulk
# =========================================================

@client.tree.command(
    name="bulk",
    description="Check up to 10 URLs at once"
)
@app_commands.describe(
    urls=(
        "Up to 10 URLs separated by "
        "spaces, commas, or new lines"
    )
)
@rate_limit
async def bulk(
    interaction: discord.Interaction,
    urls: str
):

    await interaction.response.defer()

    cleaned = (
        urls.replace(",", " ")
        .replace("\n", " ")
        .split()
    )

    targets = list(
        dict.fromkeys(
            item.strip()
            for item in cleaned
            if item.strip()
        )
    )

    if not targets:

        await interaction.followup.send(
            "❌ No URLs were provided."
        )

        return

    if len(targets) > MAX_BULK_URLS:

        await interaction.followup.send(
            (
                "❌ Bulk checks are limited to "
                f"{MAX_BULK_URLS} URLs."
            )
        )

        return

    # -----------------------------------------------------
    # Log bulk command and targets
    # -----------------------------------------------------

    logger.info(
        (
            "COMMAND "
            "command=bulk "
            "user_id=%s "
            "guild_id=%s "
            "target_count=%s"
        ),
        interaction.user.id,
        interaction.guild_id,
        len(targets)
    )

    for target in targets:

        logger.info(
            (
                "BULK_TARGET "
                "user_id=%s "
                "guild_id=%s "
                "target=%s"
            ),
            interaction.user.id,
            interaction.guild_id,
            sanitize_for_log(target)
        )

    # -----------------------------------------------------
    # Check one target
    # -----------------------------------------------------

    async def check_target(target):

        try:
            result = await check_url(
                target
            )

            log_result(
                "bulk",
                target,
                result["status"],
                result["response_time"]
            )

            return {
                "target": target,
                "success": True,
                "result": result
            }

        except Exception as error:

            log_failure(
                "bulk",
                target,
                error
            )

            return {
                "target": target,
                "success": False,
                "error": str(error)
            }

    # -----------------------------------------------------
    # Run checks concurrently
    # -----------------------------------------------------

    results = await asyncio.gather(
        *[
            check_target(
                target
            )
            for target in targets
        ]
    )

    # -----------------------------------------------------
    # Build embed
    # -----------------------------------------------------

    embed = discord.Embed(
        title="📊 HTTPScout Bulk Check",
        description=(
            f"Checked {len(targets)} target(s)"
        ),
        color=discord.Color.blue()
    )

    successful = 0
    failed = 0

    for item in results:

        if item["success"]:

            successful += 1

            result = item["result"]

            _, icon = get_status_style(
                result["status"]
            )

            value = (
                "```"
                f"{icon} {result['status']}\n"
                f"{result['response_time']} ms\n"
                f"{len(result['redirects'])} redirect(s)"
                "```"
            )

        else:

            failed += 1

            value = (
                "```"
                f"❌ {item['error'][:150]}"
                "```"
            )

        embed.add_field(
            name=item["target"][:256],
            value=value,
            inline=True
        )

    # -----------------------------------------------------
    # Summary
    # -----------------------------------------------------

    embed.add_field(
        name="Summary",
        value=(
            "```"
            f"Successful: {successful}\n"
            f"Failed:     {failed}\n"
            f"Total:      {len(targets)}"
            "```"
        ),
        inline=False
    )

    embed.set_footer(
        text=(
            "HTTPScout • "
            f"Maximum {MAX_BULK_URLS} URLs"
        )
    )

    logger.info(
        (
            "BULK_SUMMARY "
            "user_id=%s "
            "guild_id=%s "
            "successful=%s "
            "failed=%s "
            "total=%s"
        ),
        interaction.user.id,
        interaction.guild_id,
        successful,
        failed,
        len(targets)
    )

    await interaction.followup.send(
        embed=embed
    )


# =========================================================
# /dns
# =========================================================

@client.tree.command(
    name="dns",
    description="Resolve public IPv4 and IPv6 addresses"
)
@app_commands.describe(
    target="Hostname or URL to resolve"
)
@rate_limit
async def dns(
    interaction: discord.Interaction,
    target: str
):

    log_command(
        interaction,
        "dns",
        target
    )

    await interaction.response.defer()

    try:
        url = validate_url(
            target
        )

        hostname = urlparse(
            url
        ).hostname

        result = await resolve_public_ips(
            hostname
        )

        ipv4_text = (
            "\n".join(
                result["ipv4"]
            )
            if result["ipv4"]
            else "None"
        )

        ipv6_text = (
            "\n".join(
                result["ipv6"]
            )
            if result["ipv6"]
            else "None"
        )

        embed = discord.Embed(
            title="🌐 HTTPScout DNS",
            description=(
                "**DNS resolution for**\n"
                f"{hostname}"
            ),
            color=discord.Color.blue()
        )

        embed.add_field(
            name="IPv4",
            value=(
                "```"
                f"{ipv4_text[:950]}"
                "```"
            ),
            inline=False
        )

        embed.add_field(
            name="IPv6",
            value=(
                "```"
                f"{ipv6_text[:950]}"
                "```"
            ),
            inline=False
        )

        embed.set_footer(
            text=(
                "HTTPScout • "
                "Public addresses only"
            )
        )

        await interaction.followup.send(
            embed=embed
        )

    except Exception as error:

        log_failure(
            "dns",
            target,
            error
        )

        await interaction.followup.send(
            f"❌ `{error}`"
        )


# =========================================================
# /tls
# =========================================================

@client.tree.command(
    name="tls",
    description="Inspect a site's TLS certificate"
)
@app_commands.describe(
    url="Website or hostname to inspect"
)
@rate_limit
async def tls(
    interaction: discord.Interaction,
    url: str
):

    log_command(
        interaction,
        "tls",
        url
    )

    await interaction.response.defer()

    try:
        result = await inspect_tls(
            url
        )

        expiry = (
            f"{result['days_remaining']} days"
            if result["days_remaining"]
            is not None
            else "Unknown"
        )

        not_before = (
            result["not_before"].strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )
            if result["not_before"]
            else "Unknown"
        )

        not_after = (
            result["not_after"].strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )
            if result["not_after"]
            else "Unknown"
        )

        sans = (
            "\n".join(
                result["sans"][:12]
            )
            if result["sans"]
            else "None"
        )

        embed = discord.Embed(
            title="🔒 HTTPScout TLS",
            description=(
                "**TLS inspection for**\n"
                f"{result['hostname']}"
            ),
            color=discord.Color.blue()
        )

        embed.add_field(
            name="TLS Version",
            value=f"```{result['tls_version']}```",
            inline=True
        )

        embed.add_field(
            name="Cipher",
            value=f"```{result['cipher']}```",
            inline=True
        )

        embed.add_field(
            name="Days Remaining",
            value=f"```{expiry}```",
            inline=True
        )

        embed.add_field(
            name="Connected IP",
            value=f"```{result['ip']}```",
            inline=False
        )

        embed.add_field(
            name="Subject",
            value=(
                "```"
                f"{result['subject'][:950]}"
                "```"
            ),
            inline=False
        )

        embed.add_field(
            name="Issuer",
            value=(
                "```"
                f"{result['issuer'][:950]}"
                "```"
            ),
            inline=False
        )

        embed.add_field(
            name="Valid From",
            value=f"```{not_before}```",
            inline=True
        )

        embed.add_field(
            name="Expires",
            value=f"```{not_after}```",
            inline=True
        )

        embed.add_field(
            name="Subject Alternative Names",
            value=(
                "```"
                f"{sans[:950]}"
                "```"
            ),
            inline=False
        )

        embed.set_footer(
            text=(
                "HTTPScout • "
                "TLS certificate inspection"
            )
        )

        await interaction.followup.send(
            embed=embed
        )

    except Exception as error:

        log_failure(
            "tls",
            url,
            error
        )

        await interaction.followup.send(
            f"❌ `{error}`"
        )


# =========================================================
# /check
# =========================================================

@client.tree.command(
    name="check",
    description="Run a combined HTTP, DNS, TLS, and security check"
)
@app_commands.describe(
    url="Website or URL to inspect"
)
@rate_limit
async def check(
    interaction: discord.Interaction,
    url: str
):

    log_command(
        interaction,
        "check",
        url
    )

    await interaction.response.defer()

    try:
        http_result = await check_url(
            url
        )

        hostname = urlparse(
            http_result["final_url"]
        ).hostname

        dns_result = await resolve_public_ips(
            hostname
        )

        security_checks = get_security_headers(
            http_result["headers"]
        )

        try:
            tls_result = await inspect_tls(
                http_result["final_url"]
            )

        except Exception:
            tls_result = None

        log_result(
            "check",
            url,
            http_result["status"],
            http_result["response_time"]
        )

        color, icon = get_status_style(
            http_result["status"]
        )

        security_present = sum(
            1
            for item in security_checks
            if item["present"]
        )

        ipv4 = (
            dns_result["ipv4"][0]
            if dns_result["ipv4"]
            else "None"
        )

        ipv6 = (
            dns_result["ipv6"][0]
            if dns_result["ipv6"]
            else "None"
        )

        if tls_result:

            days = (
                tls_result["days_remaining"]
            )

            tls_text = (
                f"{tls_result['tls_version']}\n"
                f"Expires: "
                f"{days if days is not None else 'Unknown'} days"
            )

        else:

            tls_text = (
                "Unavailable / not HTTPS"
            )

        embed = discord.Embed(
            title="🔎 HTTPScout Full Check",
            description=(
                "**Combined analysis for**\n"
                f"{http_result['requested_url']}"
            ),
            color=color
        )

        embed.add_field(
            name="HTTP Status",
            value=(
                "```"
                f"{icon} {http_result['status']}"
                "```"
            ),
            inline=True
        )

        embed.add_field(
            name="Response Time",
            value=(
                "```"
                f"{http_result['response_time']} ms"
                "```"
            ),
            inline=True
        )

        embed.add_field(
            name="Redirects",
            value=(
                "```"
                f"{len(http_result['redirects'])}"
                "```"
            ),
            inline=True
        )

        embed.add_field(
            name="IPv4",
            value=f"```{ipv4}```",
            inline=True
        )

        embed.add_field(
            name="IPv6",
            value=f"```{ipv6}```",
            inline=True
        )

        embed.add_field(
            name="Security Headers",
            value=(
                "```"
                f"{security_present}/"
                f"{len(security_checks)} present"
                "```"
            ),
            inline=True
        )

        embed.add_field(
            name="TLS",
            value=f"```{tls_text}```",
            inline=False
        )

        embed.add_field(
            name="Final URL",
            value=(
                "```"
                f"{http_result['final_url']}"
                "```"
            ),
            inline=False
        )

        security_text = ""

        for item in security_checks:

            symbol = (
                "✅"
                if item["present"]
                else "❌"
            )

            security_text += (
                f"{symbol} {item['name']}\n"
            )

        embed.add_field(
            name="Security Header Summary",
            value=(
                "```"
                f"{security_text[:950]}"
                "```"
            ),
            inline=False
        )

        embed.set_footer(
            text=(
                "HTTPScout • "
                "Combined HTTP/DNS/TLS inspection"
            )
        )

        await interaction.followup.send(
            embed=embed
        )

    except Exception as error:

        log_failure(
            "check",
            url,
            error
        )

        await interaction.followup.send(
            f"❌ `{error}`"
        )


# =========================================================
# Start Bot
# =========================================================

logger.info(
    "Starting HTTPScout"
)

client.run(
    TOKEN,
    log_handler=None
)