# HTTPScout

HTTPScout is a lightweight Discord bot for checking website status, response headers, redirects, DNS records, TLS certificates, and common HTTP security headers.

It also includes bulk checks, combined reports, rate limiting, logging, and SSRF protections to help keep the bot from being abused against internal or private network targets.

## Features

- `/status` - Check HTTP status, response time, redirects, server, and content type
- `/headers` - View HTTP response headers
- `/redirects` - Inspect the redirect chain
- `/security` - Check common HTTP security headers
- `/bulk` - Check up to 10 URLs at once
- `/dns` - Resolve public IPv4 and IPv6 addresses
- `/tls` - Inspect TLS certificate information
- `/check` - Run a combined HTTP, DNS, TLS, and security check

## Safety Features

HTTPScout includes several protections intended to reduce abuse:

- Blocks private IP ranges
- Blocks localhost and loopback addresses
- Blocks link-local addresses
- Blocks reserved and multicast addresses
- Blocks common metadata endpoints
- Restricts outbound requests to ports `80` and `443`
- Validates redirect destinations
- Limits redirects
- Limits concurrent requests
- Per-user rate limiting
- Request timeouts
- Bulk-check limit of 10 URLs

## Requirements

- Python 3.11+
- Discord bot application
- Docker and Docker Compose if running in a container

Python dependencies:

```text
discord.py
aiohttp
python-dotenv
