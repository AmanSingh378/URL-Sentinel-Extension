
import asyncio
import ipaddress
import socket
import ssl
import time

from urllib.parse import urljoin, urlparse

import httpx


MAX_REDIRECTS = 5
REQUEST_TIMEOUT = 10.0


def validate_public_url(url: str) -> tuple[str, list[str]]:
    """Validate a URL and reject non-public DNS/IP destinations."""
    try:
        parsed = urlparse(url.strip())

        if parsed.scheme not in ("http", "https"):
            raise ValueError("Only HTTP and HTTPS URLs are supported.")

        if not parsed.hostname:
            raise ValueError("Please enter a valid website URL.")

        if parsed.username or parsed.password:
            raise ValueError("URLs containing login credentials are not allowed.")

        hostname = parsed.hostname.rstrip(".").lower()

        if hostname == "localhost" or hostname.endswith(".localhost"):
            raise ValueError("Localhost addresses cannot be diagnosed.")

        if hostname.endswith(".local"):
            raise ValueError("Local network addresses cannot be diagnosed.")

        try:
            ip = ipaddress.ip_address(hostname)
            addresses = [str(ip)]
        except ValueError:
            records = socket.getaddrinfo(
                hostname,
                parsed.port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            )
            addresses = list({record[4][0] for record in records})

        if not addresses:
            raise ValueError("The domain did not resolve to an IP address.")

        for address in addresses:
            ip = ipaddress.ip_address(address)
            if not ip.is_global:
                raise ValueError(
                    "The website resolves to a private or non-public IP address."
                )

        normalized = parsed._replace(
            netloc=parsed.netloc,
            fragment="",
        ).geturl()

        return normalized, addresses

    except socket.gaierror as exc:
        raise ValueError(
            "DNS lookup failed. The domain may not exist or DNS may be unavailable."
        ) from exc


def inspect_tls(hostname: str, port: int = 443) -> dict:
    """Inspect a public HTTPS server's TLS certificate."""
    result = {
        "checked": False,
        "valid": None,
        "issuer": None,
        "expires_at": None,
        "error": None,
    }

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, port), timeout=REQUEST_TIMEOUT
        ) as raw_socket:
            with context.wrap_socket(
                raw_socket, server_hostname=hostname
            ) as tls_socket:
                cert = tls_socket.getpeercert()

                result["checked"] = True
                result["valid"] = True
                result["expires_at"] = cert.get("notAfter")

                issuer_parts = cert.get("issuer", ())
                result["issuer"] = ", ".join(
                    "=".join(part) for group in issuer_parts for part in group
                )

    except ssl.SSLCertVerificationError as exc:
        result["checked"] = True
        result["valid"] = False
        result["error"] = str(exc)

    except (OSError, ssl.SSLError, ValueError) as exc:
        result["error"] = str(exc)

    return result


async def diagnose_website(url: str) -> dict:
    """Run DNS, TLS, HTTP, latency and redirect diagnostics."""
    current_url, addresses = validate_public_url(url)

    dns_result = {
        "resolved": True,
        "addresses": addresses,
        "error": None,
    }

    parsed_initial = urlparse(current_url)
    tls_result = {
        "checked": False,
        "valid": None,
        "issuer": None,
        "expires_at": None,
        "error": None,
    }

    if parsed_initial.scheme == "https":
        tls_result = await asyncio.to_thread(
            inspect_tls,
            parsed_initial.hostname,
            parsed_initial.port or 443,
        )

    redirects = []
    status_code = None
    latency_ms = None
    final_url = current_url
    http_error = None

    try:
        async with httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT,
            follow_redirects=False,
            verify=True,
            trust_env=False,
            headers={"User-Agent": "URL-Sentinel-Diagnostics/1.0"},
        ) as client:
            for hop in range(MAX_REDIRECTS + 1):
                # Revalidate every destination before making a request.
                current_url, _ = validate_public_url(current_url)

                started = time.perf_counter()

                async with client.stream("GET", current_url) as response:
                    latency_ms = round(
                        (time.perf_counter() - started) * 1000, 2
                    )
                    status_code = response.status_code
                    final_url = current_url

                    location = response.headers.get("location")

                    if status_code not in (301, 302, 303, 307, 308):
                        break

                    if not location:
                        break

                    if hop == MAX_REDIRECTS:
                        http_error = "Redirect limit exceeded."
                        break

                    next_url = urljoin(current_url, location)
                    redirects.append({
                        "status_code": status_code,
                        "from": current_url,
                        "to": next_url,
                    })
                    current_url = next_url

    except httpx.ConnectTimeout:
        http_error = "Connection timed out."
    except httpx.ReadTimeout:
        http_error = "The server took too long to respond."
    except httpx.ConnectError as exc:
        http_error = f"Connection failed: {exc}"
    except httpx.HTTPError as exc:
        http_error = f"HTTP request failed: {exc}"
    except ValueError as exc:
        http_error = str(exc)

    if status_code is not None and status_code >= 500:
        diagnosis = "The website server may be experiencing an internal error."
    elif status_code is not None and status_code >= 400:
        diagnosis = "The server returned an HTTP client error."
    elif http_error:
        diagnosis = http_error
    elif status_code is not None:
        diagnosis = "The website returned an HTTP response."
    else:
        diagnosis = "The website could not be reached."

    return {
        "url": url,
        "final_url": final_url,
        "dns": dns_result,
        "tls": tls_result,
        "http": {
            "status_code": status_code,
            "latency_ms": latency_ms,
            "error": http_error,
        },
        "redirects": redirects,
        "redirect_count": len(redirects),
        "diagnosis": diagnosis,
    }
