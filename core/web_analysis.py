"""Bounded, read-only HTTP surface inspection for an explicitly authorized URL."""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

MAX_RESPONSE_BYTES = 1_000_000
MAX_LINKS = 100
MAX_REDIRECTS = 2
MAX_CRAWL_PAGES = 20
_TIMEOUT = 4


class WebTargetError(ValueError):
    """The supplied URL is invalid or escaped its explicitly selected origin."""


def _origin(parsed):
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), port


def _validated_url(value):
    if not isinstance(value, str) or len(value) > 2048:
        raise WebTargetError("Enter a URL no longer than 2048 characters.")
    parsed = urlsplit(value.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise WebTargetError("Only HTTP and HTTPS website URLs are supported.")
    if parsed.username is not None or parsed.password is not None:
        raise WebTargetError("URLs containing embedded credentials are not accepted.")
    if parsed.query:
        raise WebTargetError("Remove query parameters before analysis so tokens or personal data are not stored or requested.")
    if parsed.fragment:
        parsed = parsed._replace(fragment="")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise WebTargetError("The URL contains an invalid port.") from exc
    if not parsed.path:
        parsed = parsed._replace(path="/")
    return parsed


def _resolve(host, port):
    try:
        literal = ipaddress.ip_address(host)
        addresses = [str(literal)]
    except ValueError:
        try:
            addresses = list(dict.fromkeys(item[4][0] for item in socket.getaddrinfo(
                host, port, type=socket.SOCK_STREAM)))
        except OSError as exc:
            raise WebTargetError("The target host did not resolve.") from exc
    if not addresses:
        raise WebTargetError("The target host did not resolve to an address.")
    parsed_addresses = []
    for value in addresses:
        address = ipaddress.ip_address(value)
        if address.is_unspecified or address.is_multicast or address.is_link_local or address.is_reserved:
            raise WebTargetError("The target resolves to an unsupported special-purpose address.")
        parsed_addresses.append(str(address))
    # One validated address is pinned for this request, preventing a second DNS lookup on connect.
    return parsed_addresses[0]


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, address, port, timeout):
        super().__init__(host, port=port, timeout=timeout)
        self._address = address

    def connect(self):
        self.sock = socket.create_connection((self._address, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, address, port, timeout):
        super().__init__(host, port=port, timeout=timeout, context=ssl.create_default_context())
        self._address = address

    def connect(self):
        raw = socket.create_connection((self._address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def _fetch_same_origin(url, expected_origin=None, redirect_count=0):
    parsed = _validated_url(url)
    origin = _origin(parsed)
    if expected_origin and origin != expected_origin:
        raise WebTargetError("Cross-origin navigation was blocked.")
    if redirect_count > MAX_REDIRECTS:
        raise WebTargetError("The target exceeded the redirect limit.")
    host, port = origin[1], origin[2]
    address = _resolve(host, port)
    connection_type = _PinnedHTTPS if origin[0] == "https" else _PinnedHTTP
    connection = connection_type(host, address, port, _TIMEOUT)
    path = urlunsplit(("", "", parsed.path or "/", "", ""))
    authority_host = f"[{host}]" if ":" in host else host
    if parsed.netloc and parsed.port:
        host_header = f"{authority_host}:{parsed.port}"
    else:
        host_header = authority_host
    try:
        connection.request("GET", path, headers={
            "Host": host_header,
            "User-Agent": "WiFiSentinel-Security-Review/1.0",
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
            "Connection": "close",
        })
        response = connection.getresponse()
        headers = response.getheaders()
        if response.status in {301, 302, 303, 307, 308}:
            location = next((value for key, value in headers if key.lower() == "location"), None)
            response.read(0)
            if not location:
                raise WebTargetError("The target returned a redirect without a Location header.")
            destination = _validated_url(urljoin(url, location))
            if _origin(destination) != origin:
                raise WebTargetError("Cross-origin or scheme-changing redirect was blocked.")
            return _fetch_same_origin(destination.geturl(), origin, redirect_count + 1)
        body = response.read(MAX_RESPONSE_BYTES + 1)
        return {"status": response.status, "headers": headers, "body": body[:MAX_RESPONSE_BYTES],
                "truncated": len(body) > MAX_RESPONSE_BYTES, "final_url": url}
    except WebTargetError:
        raise
    except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
        raise WebTargetError(f"The read-only request failed ({type(exc).__name__}).") from exc
    finally:
        connection.close()


class _SurfaceParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.forms = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        attributes = {str(key).lower(): value for key, value in attrs if key}
        if tag.lower() == "a" and attributes.get("href"):
            self.links.append(attributes["href"])
        if tag.lower() == "form":
            self._form = {"method": str(attributes.get("method") or "GET").upper(),
                          "action": str(attributes.get("action") or ""), "has_password_input": False}
            self.forms.append(self._form)
        elif tag.lower() == "input" and self._form and str(attributes.get("type") or "").lower() == "password":
            self._form["has_password_input"] = True

    def handle_endtag(self, tag):
        if tag.lower() == "form":
            self._form = None


def _cookie_summary(headers):
    cookies = []
    for name, value in headers:
        if name.lower() != "set-cookie":
            continue
        segments = [segment.strip() for segment in value.split(";")]
        cookie_name = segments[0].split("=", 1)[0][:80] if segments else "unknown"
        flags = {segment.split("=", 1)[0].lower() for segment in segments[1:]}
        same_site = next((segment.split("=", 1)[1][:20] for segment in segments[1:]
                          if segment.lower().startswith("samesite=")), None)
        cookies.append({"name": cookie_name, "secure": "secure" in flags,
                        "http_only": "httponly" in flags, "same_site": same_site})
    return cookies


def analyze_url(url):
    """Fetch one page with GET only and summarize same-origin surface metadata."""
    parsed = _validated_url(url)
    origin = _origin(parsed)
    response = _fetch_same_origin(parsed.geturl(), origin)
    headers = response.get("headers") or []
    header_map = {}
    for name, value in headers:
        lowered = str(name).lower()
        if lowered in {"content-security-policy", "strict-transport-security", "x-content-type-options",
                       "referrer-policy", "permissions-policy", "content-type", "server"}:
            header_map[lowered] = str(value)[:300]
    response_headers = [{"name": name, "present": name in header_map,
                         "value": header_map.get(name)} for name in (
        "content-security-policy", "strict-transport-security", "x-content-type-options",
        "referrer-policy", "permissions-policy", "content-type", "server")]
    content_type = next((str(value).lower() for name, value in headers if name.lower() == "content-type"), "")
    parser = _SurfaceParser()
    if "html" in content_type:
        parser.feed((response.get("body") or b"").decode("utf-8", errors="replace"))
    links = []
    forms = []
    for href in parser.links:
        href = href.strip()
        if not href or href.lower().startswith(("javascript:", "data:", "mailto:", "tel:")):
            continue
        try:
            target = _validated_url(urljoin(parsed.geturl(), href))
        except WebTargetError:
            continue
        if _origin(target) == origin and not target.query and target.geturl() not in links:
            links.append(target.geturl())
        if len(links) >= MAX_LINKS:
            break
    for form in parser.forms[:50]:
        action = urljoin(parsed.geturl(), form["action"] or parsed.path or "/")
        try:
            action_url = _validated_url(action)
            same_origin = _origin(action_url) == origin and not action_url.query
            action_path = action_url.path if same_origin else ""
        except WebTargetError:
            same_origin = False
            action_path = ""
        forms.append({"method": form["method"] if form["method"] in {"GET", "POST", "PUT", "PATCH", "DELETE"} else "OTHER",
                      "action_path": action_path, "same_origin": same_origin,
                      "has_password_input": form["has_password_input"]})
    indicators = []
    for header, rule in (("content-security-policy", "WEB-CSP-MISSING"),
                         ("x-content-type-options", "WEB-NOSNIFF-MISSING"),
                         ("referrer-policy", "WEB-REFERRER-POLICY-MISSING"),
                         ("permissions-policy", "WEB-PERMISSIONS-POLICY-MISSING")):
        if header not in header_map:
            indicators.append({"rule_id": rule, "title": f"{header} header not observed",
                "severity": "Low", "confidence": "Observed",
                "description": "This response did not include the reviewed header. The observation alone does not prove an exploitable vulnerability.",
                "recommendation": "Review whether this header is appropriate for the application and set it consistently at the application or edge."})
    if origin[0] == "https" and "strict-transport-security" not in header_map:
        indicators.append({"rule_id": "WEB-HSTS-MISSING", "title": "HTTP Strict Transport Security header not observed",
            "severity": "Low", "confidence": "Observed",
            "description": "The HTTPS response did not include Strict-Transport-Security.",
            "recommendation": "If the domain is HTTPS-only and all subdomains are ready, consider a carefully staged HSTS policy."})
    cookies = _cookie_summary(headers)
    for cookie in cookies:
        if cookie["name"].lower().startswith(("session", "auth", "token")):
            missing = [flag for flag, present in (("Secure", cookie["secure"]), ("HttpOnly", cookie["http_only"])) if not present]
            if missing:
                indicators.append({"rule_id": "WEB-SESSION-COOKIE-FLAGS", "title": "Session-like cookie missing security flags",
                    "severity": "Medium", "confidence": "Observed",
                    "description": f"Cookie named {cookie['name']} did not include {', '.join(missing)}. Its value was not collected.",
                    "recommendation": "Review cookie scope and set Secure and HttpOnly where appropriate; also review SameSite behavior."})
    display_host = f"[{origin[1]}]" if ":" in origin[1] else origin[1]
    return {"method": "read-only GET; no forms submitted", "target_origin": f"{origin[0]}://{display_host}:{origin[2]}",
        "requested_path": parsed.path or "/", "status_code": response.get("status"),
        "response_truncated": bool(response.get("truncated")), "headers": response_headers,
        "links": links, "forms": forms, "cookies": cookies, "indicator_count": len(indicators),
        "indicators": indicators, "limitations": [
            "This is one-page HTTP surface inspection, not a full crawl, authentication test, source review, or vulnerability scan.",
            "Only same-origin links and metadata were considered; no forms or state-changing requests were sent.",
            "Response bodies, cookie values, query parameters, and form values are not persisted.",
        ]}


def analyze_site(url, max_pages=MAX_CRAWL_PAGES):
    """Crawl observed same-origin links using bounded GET requests only.

    There is no browser execution, authentication, form submission, query-string
    request, or access to cross-origin links. API routes are labelled by a
    path-shape heuristic over routes actually observed in links.
    """
    parsed = _validated_url(url)
    try:
        limit = int(max_pages)
    except (TypeError, ValueError) as exc:
        raise WebTargetError("Page limit must be an integer from 1 to 20.") from exc
    if isinstance(max_pages, bool) or limit < 1 or limit > MAX_CRAWL_PAGES:
        raise WebTargetError("Page limit must be an integer from 1 to 20.")

    origin = _origin(parsed)
    start = parsed.geturl()
    queue = [start]
    queued = {start}
    pages = []
    indicators = []
    routes = []
    truncated = False
    while queue and len(pages) < limit:
        current = queue.pop(0)
        page = analyze_url(current)
        route = urlsplit(current).path or "/"
        routes.append(route)
        content_type = next((item["value"] for item in page["headers"]
                             if item["name"] == "content-type" and item["present"]), None)
        pages.append({
            "path": route,
            "status_code": page["status_code"],
            "content_type": content_type,
            "response_truncated": page["response_truncated"],
            "links": page["links"],
            "forms": page["forms"],
            "indicator_count": page["indicator_count"],
        })
        truncated = truncated or page["response_truncated"]
        for indicator in page["indicators"]:
            indicators.append({**indicator, "path": route})
        for link in page["links"]:
            target = _validated_url(link)
            normalized = target.geturl()
            if _origin(target) == origin and normalized not in queued and len(queued) < MAX_LINKS + 1:
                queued.add(normalized)
                queue.append(normalized)

    inventory = sorted(set(routes))
    api_routes = sorted(route for route in inventory if
                        route.lower().startswith("/api/") or "/api/" in route.lower() or
                        route.lower().endswith((".json", ".graphql")))
    display_host = f"[{origin[1]}]" if ":" in origin[1] else origin[1]
    return {
        "execution": "read_only_same_origin_get",
        "method": "bounded same-origin HTTP GET; no forms submitted",
        "target_origin": f"{origin[0]}://{display_host}:{origin[2]}",
        "requested_path": parsed.path or "/",
        "max_pages": limit,
        "pages_scanned": len(pages),
        "page_limit_reached": bool(queue),
        "response_truncated": truncated,
        "pages": pages,
        "route_inventory": inventory,
        "api_routes": api_routes,
        "indicator_count": len(indicators),
        "indicators": indicators,
        "limitations": [
            "Only links observed in fetched HTML pages were crawled; client-side routes and unlinked endpoints are not discovered.",
            "API routes are a path-shape heuristic over observed routes, not verified API endpoints.",
            "Requests are unauthenticated, query strings are rejected, forms are not submitted, and non-GET methods are not tested.",
            "Same-origin redirects and DNS are revalidated per request; cross-origin or scheme-changing redirects are blocked.",
            "A bounded route inventory is not a full vulnerability scan or proof that unobserved paths do not exist.",
        ],
    }
