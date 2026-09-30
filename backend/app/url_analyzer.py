import ipaddress
import re
from urllib.parse import parse_qsl, unquote, urlsplit

from pydantic import BaseModel, Field

from .config import settings


class URLQueryParameter(BaseModel):
    key: str
    value: str


class URLFinding(BaseModel):
    code: str
    title: str
    severity: str
    explanation: str
    evidence: str


class URLAnalysis(BaseModel):
    url: str
    protocol: str
    domain: str
    port: int | None
    path: str
    query_parameters: list[URLQueryParameter]
    risk_level: str
    risk_score: int = Field(ge=0, le=100)
    findings: list[URLFinding]
    explanation: str
    recommended_actions: list[str]
    assessment_type: str = "heuristic"
    demo_mode: bool


BRAND_DOMAINS = {
    "amazon": ("amazon.com", "amazon.co.uk", "amazon.in", "amazon.ca", "amazon.de"),
    "apple": ("apple.com", "icloud.com"),
    "facebook": ("facebook.com", "fb.com", "meta.com"),
    "google": ("google.com", "google.co.uk", "google.co.in", "gmail.com"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "outlook.com"),
    "netflix": ("netflix.com",),
    "paypal": ("paypal.com",),
    "whatsapp": ("whatsapp.com",),
}

SUSPICIOUS_KEYWORDS = (
    "account", "billing", "claim", "gift", "login", "password", "payment", "prize",
    "recover", "security", "signin", "support", "urgent", "verify", "wallet",
)


def _finding(code: str, title: str, severity: str, explanation: str, evidence: str, weight: int) -> tuple[URLFinding, int]:
    return URLFinding(code=code, title=title, severity=severity, explanation=explanation, evidence=evidence), weight


def analyze_url(raw_url: str) -> URLAnalysis:
    """Inspect URL syntax locally; this function never resolves or visits the host."""
    url = raw_url.strip()
    if not url:
        raise ValueError("Enter a URL to check.")
    if len(url) > 8192:
        raise ValueError("URL is too long. The maximum supported length is 8,192 characters.")
    if any(ord(char) <= 0x20 or ord(char) == 0x7F for char in url):
        raise ValueError("URL contains spaces or control characters. Encode spaces and remove control characters.")

    try:
        parsed = urlsplit(url)
        protocol = parsed.scheme.lower()
        domain = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Enter a valid HTTP or HTTPS URL with a valid host and port.") from exc

    if protocol not in {"http", "https"} or not parsed.netloc or not domain:
        raise ValueError("Enter a valid HTTP or HTTPS URL, such as https://example.com/path.")
    if any(char in domain for char in "/\\@%?#"):
        raise ValueError("The URL hostname is malformed.")

    try:
        ascii_domain = domain.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise ValueError("The URL hostname is not valid.") from exc
    try:
        ipaddress.ip_address(domain.split("%", 1)[0])
        is_ip = True
    except ValueError:
        is_ip = False
        labels = ascii_domain.split(".")
        if not ascii_domain or len(ascii_domain) > 253 or any(
            not label
            or len(label) > 63
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        ):
            raise ValueError("The URL hostname is not valid.")

    try:
        query_parameters = [
            URLQueryParameter(key=key, value=value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=128)
        ]
    except ValueError as exc:
        raise ValueError("The URL has too many query parameters to analyze safely.") from exc

    findings_with_weight: list[tuple[URLFinding, int]] = []
    host_lower = domain.lower().rstrip(".")
    hostname_labels = ascii_domain.split(".")
    subdomain_count = max(0, len(hostname_labels) - 2)

    if protocol == "http":
        findings_with_weight.append(_finding(
            "http_without_tls", "Uses HTTP instead of HTTPS", "low",
            "The connection scheme is not encrypted in transit. This alone does not establish malicious intent.",
            "http://", 16,
        ))
    if is_ip:
        findings_with_weight.append(_finding(
            "ip_address_host", "Uses an IP address as the hostname", "medium",
            "An IP address is used directly instead of a human-readable domain. This can be legitimate, but deserves extra verification.",
            domain, 34,
        ))
    if len(url) > 2048:
        findings_with_weight.append(_finding(
            "very_long_url", "Unusually long URL", "low",
            "Long URLs can make the true destination or redirect path harder to inspect.",
            f"{len(url)} characters", 12,
        ))
    if subdomain_count >= 4:
        findings_with_weight.append(_finding(
            "many_subdomains", "Many subdomain labels", "low",
            "Several labels appear before the registered-domain portion, which can make the hostname harder to read.",
            f"{subdomain_count} subdomain labels", 14,
        ))

    malformed_escape = re.search(r"%(?![0-9a-fA-F]{2})", url)
    suspicious_escape = re.search(r"%(?:2f|5c|2e|40|25(?:2f|5c|2e|40))", url, re.IGNORECASE)
    if malformed_escape or suspicious_escape:
        evidence = malformed_escape.group(0) if malformed_escape else suspicious_escape.group(0)
        findings_with_weight.append(_finding(
            "suspicious_encoding", "Suspicious or malformed percent encoding", "medium",
            "The URL contains malformed escapes or encoded separators that can obscure how parts of the address are interpreted.",
            evidence, 18,
        ))

    decoded_address = unquote(parsed.path + "?" + parsed.query).lower()
    matched_keywords = [word for word in SUSPICIOUS_KEYWORDS if re.search(rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])", host_lower + " " + decoded_address)]
    if matched_keywords:
        findings_with_weight.append(_finding(
            "suspicious_keywords", "Contains attention-grabbing or account-related words", "low",
            "Words associated with sign-in, account recovery, prizes, or urgency appear in the address. These words are also used on legitimate sites.",
            ", ".join(matched_keywords[:8]), 12,
        ))

    host_tokens = set(re.split(r"[^a-z0-9]+", host_lower))
    address_tokens = set(re.split(r"[^a-z0-9]+", decoded_address))
    mentioned_brands = [brand for brand in BRAND_DOMAINS if brand in host_tokens or brand in address_tokens]
    mismatched_brands = [
        brand for brand in mentioned_brands
        if not any(host_lower == official or host_lower.endswith("." + official) for official in BRAND_DOMAINS[brand])
    ]
    if mismatched_brands:
        findings_with_weight.append(_finding(
            "brand_domain_mismatch", "Brand name appears on a different domain", "medium",
            "A familiar brand name appears in the hostname, path, or query while the hostname does not match the known domain pattern checked by this heuristic.",
            ", ".join(mismatched_brands), 24,
        ))

    unicode_domain = any(ord(char) > 127 for char in domain)
    punycode_labels = [label for label in hostname_labels if label.startswith("xn--")]
    if unicode_domain or punycode_labels:
        evidence = ", ".join(punycode_labels) if punycode_labels else domain
        findings_with_weight.append(_finding(
            "idn_or_punycode", "Internationalized or punycode hostname", "medium",
            "The hostname uses internationalized characters or punycode. Similar-looking characters can be confusing; this is not proof of impersonation.",
            evidence, 20,
        ))

    risk_score = min(100, sum(weight for _, weight in findings_with_weight))
    risk_level = "high" if risk_score >= 60 else "medium" if risk_score >= 28 else "low"
    findings = [finding for finding, _ in findings_with_weight]

    if findings:
        explanation = (
            f"This heuristic review found {len(findings)} structural indicator(s). "
            "They can help prioritize verification, but do not confirm that the URL is malicious."
        )
    else:
        explanation = (
            "No listed structural indicators were found. This local heuristic check does not verify the site's reputation "
            "and cannot confirm that the URL is safe."
        )

    if risk_level == "high":
        actions = [
            "Do not enter credentials or payment details on this page.",
            "If the link claims to be from a known organization, open its official app or type its known address yourself.",
            "Ask the sender through a separate trusted channel before acting.",
        ]
    elif findings:
        actions = [
            "Check the registered domain carefully before opening the address.",
            "Verify the link through the organization's official app or a contact method you already trust.",
            "Do not enter passwords, verification codes, or payment information unless you independently trust the site.",
        ]
    else:
        actions = [
            "Confirm the domain is the one you intended to visit before entering information.",
            "Treat unexpected requests for credentials, verification codes, or payment with caution.",
        ]

    return URLAnalysis(
        url=url,
        protocol=protocol,
        domain=domain,
        port=port,
        path=parsed.path or "/",
        query_parameters=query_parameters,
        risk_level=risk_level,
        risk_score=risk_score,
        findings=findings,
        explanation=explanation,
        recommended_actions=actions,
        assessment_type="heuristic",
        demo_mode=settings.demo_mode,
    )
