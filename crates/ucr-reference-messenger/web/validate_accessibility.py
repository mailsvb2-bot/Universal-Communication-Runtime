#!/usr/bin/env python3
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
HTML = (ROOT / "index.html").read_text(encoding="utf-8")
CSS = (ROOT / "styles.css").read_text(encoding="utf-8")
JS = (ROOT / "app.js").read_text(encoding="utf-8")
CAPTIONS = (ROOT / "captions.vtt").read_text(encoding="utf-8")
SUBTITLES = (ROOT / "subtitles.vtt").read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


class EvidenceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))


parser = EvidenceParser()
parser.feed(HTML)
ids = {attrs["id"] for _, attrs in parser.tags if attrs.get("id")}
controls = {"input", "select", "textarea"}

require(any(tag == "html" and attrs.get("lang") and attrs.get("dir") == "ltr" and attrs.get("data-ucr-boundary") == "presentation-only" for tag, attrs in parser.tags), "browser boundary/language/direction marker missing")
require(any(tag == "script" and attrs.get("src") == "app.js" and "defer" in attrs for tag, attrs in parser.tags), "accessibility behavior script missing")
require(any(tag == "a" and "skip-link" in (attrs.get("class") or "") for tag, attrs in parser.tags), "skip link missing")
require(any(attrs.get("role") == "log" and attrs.get("aria-live") == "polite" for _, attrs in parser.tags), "screen-reader message log missing")
require(any(tag == "nav" and attrs.get("aria-label") for tag, attrs in parser.tags), "named navigation landmark missing")
require(any(tag == "form" and attrs.get("aria-label") for tag, attrs in parser.tags), "named message form missing")
require(any(tag == "button" and attrs.get("id") == "direction-toggle" and attrs.get("aria-pressed") == "false" for tag, attrs in parser.tags), "RTL toggle semantics missing")
require(any(tag == "button" and attrs.get("id") == "contrast-toggle" and attrs.get("aria-pressed") == "false" for tag, attrs in parser.tags), "contrast toggle semantics missing")
require(any(tag == "select" and attrs.get("id") == "text-scale" for tag, attrs in parser.tags), "text scale control missing")
require(any(attrs.get("id") == "accessibility-status" and attrs.get("role") == "status" and attrs.get("aria-live") == "polite" for _, attrs in parser.tags), "accessibility change announcement surface missing")
for tag, attrs in parser.tags:
    if "tabindex" in attrs:
        require(int(attrs["tabindex"] or "0") <= 0, "positive tabindex is forbidden")
    if tag == "label" and attrs.get("for"):
        require(attrs["for"] in ids, f"label target missing: {attrs['for']}")
require(all(tag not in {"div", "span"} or "tabindex" not in attrs for tag, attrs in parser.tags), "custom div/span keyboard controls are forbidden")
require(any(tag == "button" for tag, _ in parser.tags) and any(tag in controls for tag, _ in parser.tags), "native keyboard controls missing")
tracks = [attrs for tag, attrs in parser.tags if tag == "track"]
require(any(attrs.get("kind") == "captions" and attrs.get("srclang") and attrs.get("label") for attrs in tracks), "caption track missing")
require(any(attrs.get("kind") == "subtitles" and attrs.get("srclang") and attrs.get("label") for attrs in tracks), "subtitle track missing")
require(any(attrs.get("id") == "transcript" and attrs.get("aria-live") == "polite" for _, attrs in parser.tags), "live transcript surface missing")
require('dir="auto"' in HTML and 'lang="ar"' in HTML, "direction-aware content evidence missing")
require(":root" in CSS and "font-size: 100%" in CSS and "1rem" in CSS, "scalable text units missing")
require('data-text-scale="125"' in CSS and 'data-text-scale="150"' in CSS, "explicit text scaling states missing")
require("px" not in CSS, "fixed px sizing is forbidden in accessibility evidence")
require(":focus-visible" in CSS, "visible keyboard focus missing")
require("prefers-contrast: more" in CSS and "forced-colors: active" in CSS and 'data-contrast="high"' in CSS, "high-contrast evidence missing")
require('[dir="rtl"]' in CSS, "RTL layout rule missing")
for required in ('directionToggle.addEventListener("click"', 'root.dir = nextDirection', 'root.dataset.textScale = textScale.value', 'contrastToggle.addEventListener("click"', 'root.dataset.contrast = "high"', 'setAttribute("aria-pressed"', 'announce('):
    require(required in JS, f"interactive accessibility wiring missing: {required}")
for forbidden in ("fetch(", "WebSocket", "RTCPeerConnection", "navigator.mediaDevices", "navigator.bluetooth", "localStorage", "sessionStorage"):
    require(forbidden not in JS, f"presentation-only browser surface gained forbidden capability: {forbidden}")
require(CAPTIONS.startswith("WEBVTT") and "-->" in CAPTIONS, "valid caption fixture missing")
require(SUBTITLES.startswith("WEBVTT") and "-->" in SUBTITLES, "valid subtitle fixture missing")
print("ACCESSIBILITY_WEB_EVIDENCE_OK")
