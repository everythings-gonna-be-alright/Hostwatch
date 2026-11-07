#!/usr/bin/env python3
"""Builds the documentation page of the website from docs/reference.md.

    python3 scripts/build-docs.py        (run from the repo root; writes docs/docs/index.html)

The reference stays the one source: GitHub shows the markdown, the website shows this page, in the main site's
style (fonts, colours, spacing). Only the markdown the reference uses is supported: headings, paragraphs, nested
and numbered lists, tables, fenced code, inline code, bold, italic and links. No dependencies.
"""
import html
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "reference.md"                  # the front page: intro and the list of chapters
CHAPTERS = ROOT / "docs" / "reference"               # one Markdown file per chapter (NN-name.md)
OUT_DIR = ROOT / "docs" / "docs"                     # index.html (overview) and one page per chapter
PAGES = {}                                           # "03-features.md" -> "features.html" (filled by main)
SITE = "https://hostwatch.tech/"
REPO = "https://github.com/everythings-gonna-be-alright/Hostwatch"


def slug(text):
    s = re.sub(r"<[^>]+>", "", text)
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s or "section"


def inline(text):
    """Escape, then apply inline markdown (code spans first, so their contents stay literal)."""
    codes = []

    def keep(m):
        codes.append("<code>" + html.escape(m.group(1)) + "</code>")
        return f"\x00{len(codes) - 1}\x00"

    text = re.sub(r"`([^`]+)`", keep, text)
    text = html.escape(text, quote=False)

    def link(m):
        label, url = m.group(1), m.group(2)
        page = re.match(r"^(?:reference/)?(\d\d-[a-z0-9-]+\.md)(#.*)?$", url)
        if page and page.group(1) in PAGES:              # another chapter: its page
            url = PAGES[page.group(1)] + (page.group(2) or "")
        elif url.endswith(".md") or ".md#" in url:        # other repo files go to GitHub
            url = f"{REPO}/blob/main/" + re.sub(r"^(\.\./)+", "", url)
        external = url.startswith("http")
        attrs = ' target="_blank" rel="noopener"' if external else ""
        return f'<a href="{html.escape(url)}"{attrs}>{label}</a>'

    text = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", link, text)
    text = re.sub(r"&lt;(https?://[^\s&]+)&gt;", r'<a href="\1" target="_blank" rel="noopener">\1</a>', text)   # <https://…> autolinks
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"(?<![\w*])\*([^*\n]+)\*(?![\w*])", r"<i>\1</i>", text)
    text = re.sub(r"\x00(\d+)\x00", lambda m: codes[int(m.group(1))], text)
    return text


def convert(md, seen=None):
    lines = md.split("\n")
    out, toc = [], []
    i, n = 0, len(lines)
    para = []
    seen = {} if seen is None else seen

    def flush():
        if para:
            out.append("<p>" + inline(" ".join(x.strip() for x in para)) + "</p>")
            para.clear()

    def unique(s):
        seen[s] = seen.get(s, 0) + 1
        return s if seen[s] == 1 else f"{s}-{seen[s]}"

    while i < n:
        line = lines[i]
        if line.startswith("```"):
            flush()
            lang = line[3:].strip()
            j = i + 1
            code = []
            while j < n and not lines[j].startswith("```"):
                code.append(lines[j])
                j += 1
            out.append(f'<pre data-lang="{html.escape(lang)}"><code>' + html.escape("\n".join(code)) + "</code></pre>")
            i = j + 1
            continue
        m = re.match(r"^(#{1,4})\s+(.*)$", line)
        if m:
            flush()
            level, text = len(m.group(1)), m.group(2).strip()
            if level == 1:                                  # the page has its own title
                i += 1
                continue
            sid = unique(slug(text))
            out.append(f'<h{level} id="{sid}"><a class="anchor" href="#{sid}" aria-label="Link to this section">#</a>{inline(text)}</h{level}>')
            toc.append((level, sid, re.sub(r"<[^>]+>", "", inline(text))))
            i += 1
            continue
        if line.startswith("|") and i + 1 < n and re.match(r"^\|[\s:|-]+\|\s*$", lines[i + 1]):
            flush()
            head = [c.strip() for c in line.strip().strip("|").split("|")]
            rows = []
            j = i + 2
            while j < n and lines[j].startswith("|"):
                rows.append([c.strip() for c in lines[j].strip().strip("|").split("|")])
                j += 1
            t = ['<div class="table"><table><thead><tr>' + "".join(f"<th>{inline(c)}</th>" for c in head) + "</tr></thead><tbody>"]
            for r in rows:
                t.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>")
            t.append("</tbody></table></div>")
            out.append("".join(t))
            i = j
            continue
        if re.match(r"^\s*([-*]|\d+\.)\s+", line):
            flush()
            j, block = i, []
            while j < n and (re.match(r"^\s*([-*]|\d+\.)\s+", lines[j]) or (lines[j].startswith("  ") and lines[j].strip())):
                block.append(lines[j])
                j += 1
            out.append(render_list(block))
            i = j
            continue
        if not line.strip():
            flush()
            i += 1
            continue
        para.append(line)
        i += 1
    flush()
    return "\n".join(out), toc


def render_list(block):
    """Nested lists by indentation; continuation lines join the item above them."""
    items = []                                              # (indent, ordered, text)
    for raw in block:
        m = re.match(r"^(\s*)([-*]|\d+\.)\s+(.*)$", raw)
        if m:
            items.append([len(m.group(1)), m.group(2)[0].isdigit(), m.group(3)])
        elif items:
            items[-1][2] += " " + raw.strip()

    def build(k, indent):
        ordered = items[k][1]
        tag = "ol" if ordered else "ul"
        parts = [f"<{tag}>"]
        while k < len(items) and items[k][0] >= indent:
            if items[k][0] > indent:
                sub, k = build(k, items[k][0])
                parts[-1] = parts[-1][: -len("</li>")] + sub + "</li>"
                continue
            parts.append(f"<li>{inline(items[k][2])}</li>")
            k += 1
        parts.append(f"</{tag}>")
        return "".join(parts), k

    result, k = [], 0
    while k < len(items):
        s, k = build(k, items[k][0])
        result.append(s)
    return "".join(result)


# Line icons for the feature groups (as the app's tab symbols where it has one: checklist, connected dots, globe).
GROUP_ICONS = {
    "learns-what-s-normal": '<path d="M2.5 4.2l1.1 1.1 2-2.2M2.5 9.7l1.1 1.1 2-2.2M7.5 4.5h6M7.5 10h6"/>',
    "connects-the-dots": '<circle cx="3.5" cy="12" r="1.6"/><circle cx="8" cy="4" r="1.6"/><circle cx="12.5" cy="11" r="1.6"/>'
                         '<path d="M4.4 10.6 7.2 5.4M8.9 5.4l2.8 4.2M5.1 11.8l5.8-.7"/>',
    "watches-the-network": '<circle cx="8" cy="8" r="6.2"/><ellipse cx="8" cy="8" rx="2.6" ry="6.2"/><path d="M1.9 6h12.2M1.9 10h12.2"/>',
    "steps-in-when-needed": '<circle cx="8" cy="8" r="6.2"/><path d="M6.4 5.4v5.2M9.6 5.4v5.2"/>',
    "knows-known-threats": '<path d="M5.5 1.8h5l3.7 3.7v5l-3.7 3.7h-5l-3.7-3.7v-5z"/><path d="M8 4.9v3.8"/>'
                           '<circle cx="8" cy="11.2" r=".6" fill="currentColor" stroke="none"/>',
    "ai-when-you-want-it": '<path d="M7 2.3l1.2 3.4 3.4 1.2-3.4 1.2L7 11.5 5.8 8.1 2.4 6.9l3.4-1.2z"/>'
                           '<path d="M12.3 10l.5 1.4 1.4.5-1.4.5-.5 1.4-.5-1.4-1.4-.5 1.4-.5z"/>',
}


SECTION_ICONS = {
    # Getting started
    "requirements": '<rect x="3.2" y="2.4" width="9.6" height="12" rx="1.6"/><path d="M6 1.6h4v1.8H6zM5.6 8.4l1.6 1.6 3.2-3.4"/>',
    "install": '<path d="M8 2.2v7.6M5 7l3 3 3-3"/><path d="M2.5 9.5v2.8c0 .8.6 1.4 1.4 1.4h8.2c.8 0 1.4-.6 1.4-1.4V9.5"/>',
    "built-in-collector": '<rect x="4" y="4" width="8" height="8" rx="1.4"/><path d="M6.4 1.8V4M9.6 1.8V4M6.4 12v2.2M9.6 12v2.2M1.8 6.4H4M1.8 9.6H4M12 6.4h2.2M12 9.6h2.2"/>',
    "baseline-the-first-hour": '<circle cx="8" cy="8" r="6.2"/><path d="M8 4.6V8l2.4 1.6"/>',
    "after-a-restart": '<path d="M13.2 8a5.2 5.2 0 1 1-1.6-3.8"/><path d="M12 1.8v2.8H9.2"/>',
    # Everyday use
    "controls-at-a-glance": '<path d="M2 4.5h12M2 11.5h12"/><circle cx="5.5" cy="4.5" r="1.6" fill="var(--bg)"/><circle cx="10.5" cy="11.5" r="1.6" fill="var(--bg)"/>',
    "hud": '<rect x="1.8" y="2.8" width="12.4" height="10.4" rx="1.8"/><rect x="8.6" y="4.6" width="3.8" height="4" rx=".8"/>',
    "window-tabs": '<rect x="1.8" y="4.6" width="12.4" height="8.6" rx="1.6"/><path d="M1.8 4.6v-.4c0-.8.6-1.4 1.4-1.4h3.4c.8 0 1.4.6 1.4 1.4v.4"/>',
    "running-now": '<path d="M1.6 8.4h2.6l1.8-4.2 3 8 1.9-4.6h3.5"/>',
    "heavy-processes": '<path d="M8 1.8c.4 2.2 3.6 3.4 3.6 7a3.6 3.6 0 0 1-7.2 0c0-1.5.8-2.5 1.6-3.3.2 1.1.8 1.7 1.4 2C7.2 5.6 7.4 3.6 8 1.8z"/>',
    "resource-use-cpu-memory-network-disk": '<path d="M2.4 13.6h11.2"/><rect x="3.4" y="8" width="2" height="4" rx=".5"/><rect x="7" y="5" width="2" height="7" rx=".5"/><rect x="10.6" y="2.6" width="2" height="9.4" rx=".5"/>',
    "time-travel": '<path d="M2.6 8a5.4 5.4 0 1 0 1.6-3.8"/><path d="M2.4 2.2v2.6H5M8 5v3l2 1.4"/>',
    # Settings
    "settings-general": '<circle cx="8" cy="8" r="2.1"/><path d="M8 1.6v1.9M8 12.5v1.9M14.4 8h-1.9M3.5 8H1.6M12.5 3.5l-1.3 1.3M4.8 11.2l-1.3 1.3M12.5 12.5l-1.3-1.3M4.8 4.8L3.5 3.5"/>',
    "settings-hud": '<rect x="1.8" y="2.8" width="12.4" height="10.4" rx="1.8"/><rect x="8.6" y="4.6" width="3.8" height="4" rx=".8"/>',
    "settings-detection": '<circle cx="7" cy="7" r="4.4"/><path d="M10.3 10.3l3.6 3.6"/>',
    "settings-firewall": '<path d="M8 1.8l5.2 2v4c0 3.1-2.2 5.3-5.2 6.4-3-1.1-5.2-3.3-5.2-6.4v-4z"/>',
    "settings-ai": '<path d="M7 2.3l1.2 3.4 3.4 1.2-3.4 1.2L7 11.5 5.8 8.1 2.4 6.9l3.4-1.2z"/><path d="M12.3 10l.5 1.4 1.4.5-1.4.5-.5 1.4-.5-1.4-1.4-.5 1.4-.5z"/>',
    "settings-exclusions": '<circle cx="8" cy="8" r="6.2"/><path d="M5.2 8h5.6"/>',
    "settings-history": '<rect x="2" y="2.6" width="12" height="3.4" rx="1"/><path d="M3.2 6v6.2c0 .7.5 1.2 1.2 1.2h7.2c.7 0 1.2-.5 1.2-1.2V6M6.4 8.6h3.2"/>',
    "exclusions": '<path d="M2 8s2.2-4.2 6-4.2S14 8 14 8s-2.2 4.2-6 4.2S2 8 2 8z"/><circle cx="8" cy="8" r="1.8"/><path d="M2.6 13.4l10.8-10.8"/>',
    "activity-history": '<path d="M2.6 8a5.4 5.4 0 1 0 1.6-3.8"/><path d="M2.4 2.2v2.6H5M8 5v3l2 1.4"/>',
    # Advanced and command line
    "command-line-flags": '<rect x="1.8" y="2.8" width="12.4" height="10.4" rx="1.8"/><path d="M4.6 6.4l2 1.8-2 1.8M8.4 10.2h3"/>',
    "how-the-collector-works": '<rect x="4" y="4" width="8" height="8" rx="1.4"/><path d="M6.4 1.8V4M9.6 1.8V4M6.4 12v2.2M9.6 12v2.2M1.8 6.4H4M1.8 9.6H4M12 6.4h2.2M12 9.6h2.2"/>',
    "updates": '<circle cx="8" cy="8" r="6.2"/><path d="M8 4.8v6M5.4 8.4L8 11l2.6-2.6"/>',
    # Privacy, security and limits
    "files-hostwatch-writes": '<path d="M1.8 4.4c0-.8.6-1.4 1.4-1.4h3l1.4 1.6h5.2c.8 0 1.4.6 1.4 1.4v6c0 .8-.6 1.4-1.4 1.4H3.2c-.8 0-1.4-.6-1.4-1.4z"/>',
    "security-notes": '<rect x="3" y="7" width="10" height="7" rx="1.6"/><path d="M5.2 7V5.2a2.8 2.8 0 0 1 5.6 0V7"/>',
    "reset-hostwatch": '<path d="M2.8 8a5.2 5.2 0 1 0 1.6-3.8"/><path d="M4 1.8v2.8h2.8"/>',
    "troubleshooting": '<path d="M10.2 2.2a3.4 3.4 0 0 0-3.9 4.5L2.4 10.6a1.4 1.4 0 0 0 2 2l3.9-3.9a3.4 3.4 0 0 0 4.5-3.9l-2 2-1.8-.3-.3-1.8z"/>',
    "known-limitations": '<path d="M8 2.2l6.2 11H1.8z"/><path d="M8 6.4v3.2"/>' + '<circle cx="8" cy="11.4" r=".55" fill="currentColor" stroke="none"/>',
    # For developers
    "build-run": '<path d="M9.4 2.4l4.2 4.2-1.6 1.6-1.4-1.4-6.4 6.4a1.1 1.1 0 0 1-1.6-1.6l6.4-6.4-1.4-1.4z"/>',
    "test": '<circle cx="8" cy="8" r="6.2"/><path d="M5.4 8.1l1.8 1.8 3.4-3.6"/>',
    "demo-mode-screenshots": '<path d="M2 5.6c0-.8.6-1.4 1.4-1.4h1.8l1.2-1.6h3.2l1.2 1.6h1.8c.8 0 1.4.6 1.4 1.4v6c0 .8-.6 1.4-1.4 1.4H3.4c-.8 0-1.4-.6-1.4-1.4z"/><circle cx="8" cy="8.6" r="2.4"/>',
    "prototype-notes": '<path d="M10.8 2.2l3 3-8 8H2.8v-3z"/><path d="M9.2 3.8l3 3"/>',
    "production-architecture": '<path d="M8 1.8l6.2 3.2L8 8.2 1.8 5z"/><path d="M1.8 8l6.2 3.2L14.2 8M1.8 11l6.2 3.2 6.2-3.2"/>',
}
GROUP_ICONS.update(SECTION_ICONS)


def group_icon(sid):
    shape = GROUP_ICONS.get(sid)
    return f'<svg class="gicon" viewBox="0 0 16 16" aria-hidden="true">{shape}</svg>' if shape else ""


def toc_html(toc):
    """Nested contents: chapters (numbered), their sections, and the features under a group."""
    root, stack = [], []
    for level, sid, text in toc:
        if level > 4:
            continue
        node = {"level": level, "id": sid, "text": text, "children": []}
        while stack and stack[-1]["level"] >= level:
            stack.pop()
        (stack[-1]["children"] if stack else root).append(node)
        stack.append(node)
    num = 0

    def render(nodes):
        nonlocal num
        out = "<ol>"
        for n in nodes:
            label = n["text"]
            if n["level"] == 2:
                num += 1
                label = f'<span class="n">{num:02d}</span>{label}'
            out += f'<li><a href="#{n["id"]}">{group_icon(n["id"])}{label}</a>'
            out += render(n["children"]) if n["children"] else ""
            out += "</li>"
        return out + "</ol>"

    return render(root)


# The event-kind icons as the app draws them (SF Symbols play.fill, network, doc.fill in system cyan, green and
# orange, dark appearance). The Markdown keeps its emoji for GitHub; the page shows these instead.
KIND_ICONS = {
    "▶ cyan": ("Process", "#64D2FF",
               '<path d="M5.2 3.1c0-.8.9-1.3 1.6-.9l7.3 4.6c.6.4.6 1.3 0 1.7l-7.3 4.6c-.7.4-1.6-.1-1.6-.9z" fill="currentColor"/>'),
    "🌐 green": ("Connection", "#30D158",
                '<g fill="none" stroke="currentColor" stroke-width="1.3"><circle cx="8" cy="8" r="6.2"/><ellipse cx="8" cy="8" rx="2.7" ry="6.2"/>'
                '<path d="M1.9 6h12.2M1.9 10h12.2"/></g>'),
    "📄 orange": ("File", "#FF9F0A",
                 '<path d="M4.3 1.6h4.9l3.6 3.6v8.4c0 .7-.6 1.3-1.3 1.3H4.3c-.7 0-1.3-.6-1.3-1.3V2.9c0-.7.6-1.3 1.3-1.3z" fill="currentColor"/>'
                 '<path d="M9.2 1.6v2.9c0 .4.3.7.7.7h2.9" fill="none" stroke="#08090a" stroke-width="1"/>'),
}


def heading_icons(html):
    for sid in GROUP_ICONS:
        html = re.sub(rf'(<h3 id="{sid}"><a class="anchor"[^>]*>#</a>)', lambda m: m.group(1) + group_icon(sid), html)
    return html


def kind_icons(html):
    for text, (label, color, shape) in KIND_ICONS.items():
        icon = (f'<span class="kind-icon" style="color:{color}" title="{label}">'
                f'<svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true">{shape}</svg>'
                f'<span class="sr">{label}</span></span>')
        html = html.replace(f"<td>{text}</td>", f"<td>{icon}</td>")
    return html


def fold_details(chapter):
    """Features read as a short tour: each section shows its heading and lead, the rest folds under Details."""
    parts = re.split(r'(?=<h[34] id=")', chapter)
    out = [parts[0]]
    for part in parts[1:]:
        m = re.match(r'(<h4 id="[^"]+">.*?</h4>\s*(?:<p>.*?</p>)?)(.*)', part, re.S)
        if not m or not m.group(2).strip():
            out.append(part)
            continue
        out.append(f'{m.group(1)}<details class="more"><summary>Details</summary>{m.group(2)}</details>')
    return "".join(out)


def chapter_section(body, prev, nxt):
    """One chapter page: its section, then the way to the previous and next chapter (page, title)."""
    pager = '<nav class="pager">'
    pager += (f'<a class="prev" href="{prev[0]}"><small>Previous</small>{prev[1]}</a>' if prev else '<span></span>')
    pager += (f'<a class="next" href="{nxt[0]}"><small>Next</small>{nxt[1]}</a>' if nxt else '<span></span>')
    pager += '</nav>'
    cls = "chapter"
    if body.lstrip().startswith('<h2 id="features">'):
        body = fold_details(body)
        cls += " features"
    return f'<section class="{cls}">{body}{pager}</section>'


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>{title}</title>
<meta name="description" content="Hostwatch documentation: how the collector, patterns, stories, firewall, Watch Closely, Running Now, Time Travel, AI and every setting work.">
<meta name="robots" content="index, follow">
<link rel="canonical" href="{site}docs/">
<meta name="theme-color" content="#08090a">
<meta name="color-scheme" content="dark">
<meta property="og:type" content="website">
<meta property="og:site_name" content="Hostwatch">
<meta property="og:url" content="{site}docs/">
<meta property="og:title" content="Hostwatch docs">
<meta property="og:description" content="Every feature, setting and rule of Hostwatch, intrusion detection for macOS.">
<meta property="og:image" content="{site}images/site/og.jpg">
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" href="../images/site/mark.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="../images/site/icon.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Instrument+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg: #08090a; --bg-raise: #0b0c0d; --line: rgba(255,255,255,0.08); --line-strong: rgba(255,255,255,0.14);
    --text: #f7f8f8; --muted: #8a8f98; --dim: #7c818a;
    --sans: "Instrument Sans", -apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif;
    --mono: "IBM Plex Mono", ui-monospace, "SF Mono", Menlo, monospace;
    --r-surface: 14px; --r-control: 10px;
  }}
  * {{ box-sizing: border-box; }}
  html {{ scroll-behavior: smooth; scroll-padding-top: 88px; }}
  body {{ margin: 0; background: var(--bg); color: var(--text); font: 400 15.5px/1.7 var(--sans); letter-spacing: -0.006em;
         -webkit-font-smoothing: antialiased; }}
  a {{ color: var(--text); text-decoration: underline; text-decoration-color: var(--line-strong); text-underline-offset: 3px; }}
  a:hover {{ text-decoration-color: var(--text); }}
  a:focus-visible, input:focus-visible {{ outline: 2px solid var(--text); outline-offset: 3px; border-radius: var(--r-control); }}

  header.top {{ position: sticky; top: 0; z-index: 10; background: rgba(8,9,10,0.82); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
               border-bottom: 1px solid var(--line); }}
  header.top .in {{ max-width: 1240px; margin: 0 auto; padding: 0 24px; height: 64px; display: flex; align-items: center; gap: 16px; }}
  .brand {{ display: flex; align-items: center; gap: 10px; font-weight: 600; font-size: 17px; letter-spacing: -0.02em; text-decoration: none; }}
  .brand .tile {{ display: grid; place-items: center; width: 34px; height: 34px; border-radius: 9px; background: linear-gradient(180deg, #1d1e20, #0b0c0d); }}
  .brand .tile svg {{ width: 26px; height: 26px; }}
  .brand .soft {{ color: var(--muted); }}
  .crumb {{ font: 500 12px var(--mono); color: var(--dim); }}
  .top .right {{ margin-left: auto; display: flex; gap: 8px; }}
  .btn {{ display: inline-flex; align-items: center; height: 34px; padding: 0 14px; border-radius: var(--r-control); font: 500 14px var(--sans);
          text-decoration: none; border: 1px solid var(--line-strong); color: var(--muted); }}
  .btn:hover {{ color: var(--text); }}
  .btn.light {{ background: var(--text); color: #08090a; border-color: var(--text); }}

  .layout {{ max-width: 1240px; margin: 0 auto; padding: 0 24px; display: grid; grid-template-columns: 300px minmax(0, 1fr); gap: 56px; }}
  nav.toc {{ position: sticky; top: 64px; align-self: start; max-height: calc(100vh - 64px); overflow: auto; padding: 28px 8px 40px 0; }}
  .search {{ position: relative; margin-bottom: 18px; }}
  .q {{ width: 100%; height: 40px; padding: 0 36px 0 12px; border-radius: var(--r-control); border: 1px solid var(--line-strong);
       background: var(--bg-raise); color: var(--text); font: 400 14px var(--sans); }}
  .q::placeholder {{ color: var(--dim); }}
  .q::-webkit-search-cancel-button {{ display: none; }}
  .search kbd {{ position: absolute; right: 10px; top: 10px; font: 500 11px/18px var(--mono); color: var(--dim); border: 1px solid var(--line-strong);
                border-radius: 5px; padding: 0 6px; }}
  .results .count {{ font: 500 12px var(--mono); color: var(--dim); padding: 0 8px 8px; }}
  nav.toc .results a {{ display: block; padding: 10px 10px; border-radius: 10px; text-decoration: none; color: var(--muted); }}
  .results a .where {{ display: block; font: 500 11px var(--mono); color: var(--dim); margin-bottom: 2px; }}
  .results a .title {{ display: block; color: var(--text); font-size: 14px; font-weight: 500; }}
  .results a .snip {{ display: block; font-size: 13px; line-height: 1.5; margin-top: 3px; }}
  nav.toc .results a.sel, nav.toc .results a:hover {{ background: rgba(255,255,255,0.06); }}
  .results .empty {{ color: var(--muted); font-size: 14px; padding: 8px; }}
  mark {{ background: rgba(255,255,255,0.18); color: var(--text); border-radius: 3px; padding: 0 1px; }}
  main mark.hit {{ background: rgba(255,255,255,0.22); box-shadow: 0 0 0 2px rgba(255,255,255,0.22); }}
  nav.toc ol {{ list-style: none; margin: 0; padding: 0; }}
  nav.toc ol ol {{ margin: 2px 0 6px 30px; }}
  nav.toc a {{ display: flex; gap: 10px; padding: 5px 8px; border-radius: 8px; color: var(--muted); text-decoration: none; font-size: 14px; line-height: 1.4; }}
  nav.toc a:hover {{ color: var(--text); background: rgba(255,255,255,0.03); }}
  nav.toc a.active {{ color: var(--text); background: rgba(255,255,255,0.05); }}
  nav.toc .n {{ font: 500 11px/1.9 var(--mono); color: var(--dim); min-width: 18px; }}

  main {{ padding: 40px 0 120px; min-width: 0; }}
  .hero {{ padding: 24px 0 40px; border-bottom: 1px solid var(--line); margin-bottom: 8px; }}
  .label {{ font: 500 13px var(--mono); color: var(--muted); display: flex; gap: 10px; align-items: center; }}
  .label::after {{ content: ""; flex: 0 0 40px; height: 1px; background: var(--line-strong); }}
  h1 {{ font-weight: 500; font-size: clamp(36px, 5vw, 56px); line-height: 1.04; letter-spacing: -0.035em; margin: 18px 0 14px; }}
  h1 .quiet {{ color: var(--dim); }}
  .hero p {{ color: var(--muted); font-size: 17px; max-width: 640px; margin: 0; }}
  .chapter {{ border-bottom: 1px solid var(--line); padding: 8px 0 32px; }}
  h2 {{ font-weight: 500; font-size: 30px; line-height: 1.15; letter-spacing: -0.025em; margin: 40px 0 14px; position: relative; }}
  h3 {{ font-weight: 500; font-size: 20px; letter-spacing: -0.015em; margin: 32px 0 10px; position: relative; }}
  h4 {{ font-weight: 600; font-size: 16px; margin: 24px 0 8px; }}
  .anchor {{ position: absolute; left: -22px; color: var(--dim); text-decoration: none; opacity: 0; font-weight: 400; }}
  h2:hover .anchor, h3:hover .anchor {{ opacity: 1; }}
  p, li {{ color: #c9ccd1; max-width: 76ch; }}
  b {{ color: var(--text); font-weight: 600; }}
  i {{ color: var(--text); font-style: normal; }}
  ul, ol {{ padding-left: 22px; }}
  li {{ margin: 6px 0; }}
  li::marker {{ color: var(--dim); }}
  /* Lists stand apart from plain text: a clear round bullet, air between items. */
  main ul {{ list-style: none; padding-left: 0; margin: 16px 0; }}
  main ul > li {{ position: relative; padding-left: 22px; margin: 12px 0; }}
  main ul > li::before {{ content: ""; position: absolute; left: 5px; top: calc(0.85em - 3px); width: 6px; height: 6px;
                          border-radius: 50%; background: var(--muted); }}
  main ul ul {{ margin: 8px 0 4px; }}
  main ul ul > li {{ margin: 6px 0; }}
  main ul ul > li::before {{ background: none; border: 1px solid var(--dim); width: 5px; height: 5px; }}
  main ol {{ padding-left: 26px; margin: 16px 0; }}
  main ol > li {{ margin: 12px 0; padding-left: 4px; }}
  main ol > li::marker {{ font: 500 12px var(--mono); color: var(--muted); }}
  code {{ font: 13px var(--mono); background: rgba(255,255,255,0.06); padding: 1px 6px; border-radius: 6px; color: #e6e8eb; }}
  pre {{ background: var(--bg-raise); border: 1px solid var(--line); border-radius: var(--r-control); padding: 16px 18px; overflow: auto; }}
  pre code {{ background: none; padding: 0; font-size: 13px; line-height: 1.6; }}
  .table {{ overflow-x: auto; margin: 16px 0; }}
  table {{ border-collapse: collapse; font-size: 14px; min-width: 60%; }}
  th, td {{ text-align: left; padding: 9px 16px 9px 0; border-bottom: 1px solid var(--line); vertical-align: top; color: #c9ccd1; }}
  th {{ font: 500 12px var(--mono); color: var(--dim); }}
  footer {{ border-top: 1px solid var(--line); padding: 32px 24px 48px; color: var(--dim); font-size: 13px; text-align: center; }}
  footer a {{ color: var(--muted); }}
  footer p {{ margin: 0 auto 6px; max-width: none; line-height: 1.9; }}
  footer a {{ white-space: nowrap; }}
  @media (max-width: 760px) {{
    footer .contact .sep {{ display: none; }}
    footer .contact > span {{ display: block; }}
    footer {{ padding-bottom: calc(88px + env(safe-area-inset-bottom)) !important; }}  /* clear of the back-to-top button */
  }}
  /* Features: groups set apart (a line, air, a muted intro), features below them. */
  .gicon {{ width: 16px; height: 16px; flex: none; fill: none; stroke: currentColor; stroke-width: 1.3; stroke-linecap: round;
            stroke-linejoin: round; margin-top: 2px; }}
  .chapter h3 .gicon {{ width: 18px; height: 18px; vertical-align: -3px; margin: 0 10px 0 0; color: var(--muted); }}
  .cards small {{ display: flex !important; align-items: center; justify-content: space-between; }}
  .cards small .gicon {{ width: 20px; height: 20px; color: var(--muted); margin: 0; }}
  .features > h3 .gicon {{ width: 20px; height: 20px; vertical-align: -3px; margin: 0 10px 0 0; color: var(--muted); }}
  nav.toc ol ol ol {{ margin: 2px 0 8px 20px; }}
  nav.toc ol ol ol a {{ font-size: 13px; padding: 6px 10px; }}
  @media (min-width: 901px) {{
    nav.toc a {{ padding: 7px 10px; }}
    nav.toc .contents > ol > li + li {{ margin-top: 4px; }}
    nav.toc .contents > ol > li > ol {{ margin: 4px 0 10px 30px; }}
    nav.toc .contents > ol > li > ol > li + li {{ margin-top: 2px; }}
  }}
  .features > h3 {{ border-top: 1px solid var(--line); padding-top: 32px; margin-top: 48px; font-size: 22px; }}
  .features > h3 + p {{ color: var(--muted); margin-top: 0; }}
  .features > h4 {{ font-size: 17px; font-weight: 500; margin: 30px 0 6px; }}
  details.more {{ margin: 4px 0 8px; }}
  details.more > summary {{ display: inline-flex; align-items: center; gap: 6px; cursor: pointer; list-style: none; color: var(--muted);
                          font-size: 14px; padding: 4px 10px; border: 1px solid var(--line-strong); border-radius: var(--r-control); }}
  details.more > summary::-webkit-details-marker {{ display: none; }}
  details.more > summary::after {{ content: "›"; color: var(--dim); transition: transform .2s; }}
  details.more[open] > summary::after {{ transform: rotate(90deg); }}
  details.more > summary:hover {{ color: var(--text); }}
  details.more[open] > summary {{ margin-bottom: 6px; }}
  nav.toc .contents > ol > li.here > ol {{ display: block; }}
  nav.toc .contents > ol > li.here.folded > ol {{ display: none !important; }}
  nav.toc .contents > ol > li.here {{ position: relative; }}
  nav.toc .fold {{ position: absolute; right: 2px; top: 4px; width: 28px; height: 28px; border: 0; border-radius: 8px; background: none;
                  color: var(--dim); cursor: pointer; display: grid; place-items: center; }}
  nav.toc .fold::before {{ content: "›"; font-size: 15px; transform: rotate(90deg); transition: transform .2s; }}
  nav.toc .folded > .fold::before {{ transform: none; }}
  nav.toc .fold:hover {{ color: var(--text); background: rgba(255,255,255,0.05); }}
  nav.toc .contents li li > ol {{ display: none; }}
  nav.toc .contents li li.open > ol {{ display: block; }}
  nav.toc .contents li li:has(> ol) > a::after {{ content: "›"; margin-left: auto; color: var(--dim); transition: transform .2s; }}
  nav.toc .contents li li.open:has(> ol) > a::after {{ transform: rotate(90deg); }}
  nav.toc .contents > ol > li.here > a {{ color: var(--text); }}
  .chapter > h2:first-child {{ font-size: clamp(32px, 4vw, 44px); letter-spacing: -0.03em; margin-top: 8px; }}
  .hero.slim {{ padding: 8px 0 0; border: 0; margin: 0; }}
  .cards {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; margin: 28px 0 8px; }}
  .cards a {{ display: block; padding: 18px 20px; border: 1px solid var(--line); border-radius: var(--r-surface); text-decoration: none; }}
  .cards a:hover {{ border-color: var(--line-strong); background: rgba(255,255,255,0.02); }}
  .cards small {{ display: block; font: 500 11px var(--mono); color: var(--dim); }}
  .cards b {{ display: block; font-size: 17px; font-weight: 500; margin: 6px 0 4px; }}
  .cards span {{ display: block; color: var(--muted); font-size: 14px; line-height: 1.55; }}
  @media (max-width: 900px) {{ .cards {{ grid-template-columns: 1fr; }} }}
  .kind-icon {{ display: inline-flex; align-items: center; vertical-align: -3px; }}
  .sr {{ position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }}
  .progress {{ position: absolute; left: 0; bottom: -1px; height: 1px; width: 0; background: var(--text); opacity: .7; }}
  .onpage {{ display: none; }}
  .pager {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 40px; }}
  .pager a {{ display: block; padding: 14px 16px; border: 1px solid var(--line); border-radius: var(--r-control); text-decoration: none;
             color: var(--text); font-weight: 500; }}
  .pager a:hover {{ border-color: var(--line-strong); background: rgba(255,255,255,0.02); }}
  .pager small {{ display: block; font: 500 11px var(--mono); color: var(--dim); margin-bottom: 4px; }}
  .pager .next {{ text-align: right; }}
  pre {{ position: relative; }}
  .copy {{ position: absolute; top: 8px; right: 8px; height: 26px; padding: 0 10px; border-radius: 7px; border: 1px solid var(--line-strong);
          background: var(--bg); color: var(--muted); font: 500 12px var(--sans); cursor: pointer; opacity: 0; transition: opacity .15s; }}
  pre:hover .copy, .copy:focus-visible {{ opacity: 1; }}
  .copy:hover {{ color: var(--text); }}
  .anchor.copied::after {{ content: "Link copied"; position: absolute; left: 22px; top: -26px; white-space: nowrap; font: 500 12px var(--sans);
                         color: var(--text); background: var(--bg-raise); border: 1px solid var(--line-strong); border-radius: 7px; padding: 3px 8px; }}
  @media (min-width: 901px) {{
    /* Only the chapter being read is expanded. */
    nav.toc .contents > ol > li > ol {{ display: none; }}
    nav.toc .contents > ol > li.current > ol {{ display: block; }}
    nav.toc .contents > ol > li.current > a {{ color: var(--text); }}
  }}
  @media (min-width: 1280px) {{
    .layout {{ max-width: 1440px; grid-template-columns: 290px minmax(0, 1fr) 210px; gap: 48px; }}
    header.top .in {{ max-width: 1440px; }}
    .onpage {{ display: block; position: sticky; top: 64px; align-self: start; max-height: calc(100vh - 64px); overflow: auto; padding: 40px 0; }}
    .onpage b {{ display: block; font: 500 12px var(--mono); color: var(--dim); margin-bottom: 10px; }}
    .onpage ol {{ list-style: none; margin: 0; padding: 0; border-left: 1px solid var(--line); }}
    .onpage a {{ display: block; padding: 5px 0 5px 14px; margin-left: -1px; border-left: 1px solid transparent; color: var(--muted);
                text-decoration: none; font-size: 13px; line-height: 1.45; }}
    .onpage a.sub {{ padding-left: 26px; font-size: 12.5px; }}
    .onpage a:hover {{ color: var(--text); }}
    .onpage a.active {{ color: var(--text); border-left-color: var(--text); }}
    .onpage-in:has(ol:empty) {{ visibility: hidden; }}
  }}
  /* Anchors land below the sticky header; long paths and commands wrap instead of widening the page. */
  h2[id], h3[id], h4[id] {{ scroll-margin-top: 84px; }}
  p, li, td {{ overflow-wrap: anywhere; }}
  p code, li code, td code {{ white-space: normal; overflow-wrap: anywhere; }}
  .contents > summary {{ display: none; }}
  .totop {{ display: none; }}
  @media (max-width: 900px) {{
    body {{ font-size: 16px; }}
    header.top .in {{ height: 56px; padding: 0 max(16px, env(safe-area-inset-left)) 0 max(16px, env(safe-area-inset-left)); }}
    .layout {{ grid-template-columns: 1fr; gap: 0; padding: 0 max(16px, env(safe-area-inset-left)); }}
    .crumb, .anchor, .top .btn:not(.light), .search kbd {{ display: none; }}
    /* Search and Contents stay at hand: a sticky bar under the header. */
    nav.toc {{ position: sticky; top: 56px; z-index: 5; max-height: calc(100dvh - 56px); overflow: auto; margin: 0 -16px;
               padding: 12px 16px; background: rgba(8,9,10,0.92); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
               border-bottom: 1px solid var(--line); }}
    .search {{ margin-bottom: 10px; }}
    .q {{ font-size: 16px; height: 44px; padding-right: 12px; }}          /* 16px: iOS doesn't zoom into the field */
    .contents > summary {{ display: flex; align-items: center; justify-content: space-between; height: 40px; padding: 0 12px;
                           border: 1px solid var(--line-strong); border-radius: var(--r-control); color: var(--muted);
                           font-size: 15px; cursor: pointer; list-style: none; }}
    .contents > summary::-webkit-details-marker {{ display: none; }}
    .contents > summary::after {{ content: "›"; color: var(--dim); transition: transform .2s; }}
    .contents[open] > summary::after {{ transform: rotate(90deg); }}
    .contents[open] > summary {{ margin-bottom: 8px; }}
    nav.toc a {{ padding: 10px 8px; font-size: 15px; }}                   /* tap targets */
    nav.toc ol ol {{ margin-left: 18px; }}
    main {{ padding: 24px 0 96px; }}
    .hero {{ padding: 12px 0 28px; }}
    h1 {{ font-size: 34px; }}
    .hero p {{ font-size: 16px; }}
    h2 {{ font-size: 24px; margin-top: 32px; }}
    h3 {{ font-size: 18px; margin-top: 26px; }}
    h2[id], h3[id], h4[id] {{ scroll-margin-top: 128px; }}
    pre {{ margin: 14px -16px; border-radius: 0; border-left: 0; border-right: 0; padding: 14px 16px; }}
    pre code {{ font-size: 12px; }}
    .table {{ margin: 14px -16px; padding: 0 16px; -webkit-overflow-scrolling: touch; }}
    table {{ font-size: 13px; min-width: 520px; }}
    th, td {{ padding: 8px 12px 8px 0; }}
    footer {{ padding-bottom: max(48px, calc(24px + env(safe-area-inset-bottom))); }}
    .totop {{ display: grid; place-items: center; position: fixed; right: max(16px, env(safe-area-inset-right));
              bottom: max(16px, env(safe-area-inset-bottom)); width: 44px; height: 44px; border-radius: 22px; z-index: 20;
              background: rgba(28,30,33,0.92); border: 1px solid var(--line-strong); color: var(--text); text-decoration: none;
              font-size: 18px; backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
              opacity: 0; pointer-events: none; transition: opacity .2s; }}
    .totop.shown {{ opacity: 1; pointer-events: auto; }}
  }}
  @media (prefers-reduced-motion: reduce) {{ html {{ scroll-behavior: auto; }} }}
</style>
</head>
<body>
<header class="top"><div class="in">
  <a class="brand" href="../"><span class="tile">{mark}</span><span>Host<span class="soft">watch</span></span></a>
  <span class="crumb">/ docs</span>
  <div class="right">
    <a class="btn" href="{edit_url}" target="_blank" rel="noopener">Edit on GitHub</a>
    <a class="btn light" href="{repo}/releases/latest">Download</a>
  </div>
</div><div class="progress" aria-hidden="true"></div></header>
<div class="layout">
  <nav class="toc" aria-label="Contents">
    <div class="search">
      <input class="q" type="search" placeholder="Search the docs" aria-label="Search the docs" autocomplete="off" spellcheck="false">
      <kbd>/</kbd>
    </div>
    <div class="results" role="listbox" aria-label="Search results" hidden></div>
    <details class="contents" open><summary>Contents</summary>{toc}</details>
  </nav>
  <main>
    {hero}
    {body}
  </main>
  <aside class="onpage" aria-label="On this page"><div class="onpage-in"><b>On this page</b><ol></ol></div></aside>
</div>
<a class="totop" href="#" aria-label="Back to top">↑</a>
<footer><p class="contact"><span>Found a bug or a mistake in the docs? <a href="{repo}/issues/new?labels=bug&amp;body=%2A%2AWhat%20happened%2A%2A%0A%0A%0A%2A%2AWhat%20you%20expected%2A%2A%0A%0A%0A%2A%2ASteps%20to%20reproduce%2A%2A%0A1.%20%0A%0A%2A%2AHostwatch%20and%20macOS%20version%2A%2A%0AHostwatch%3A%20%0AmacOS%3A%20%0A%0A%28Security%20problem%3F%20Please%20email%20it%20instead%20of%20opening%20a%20public%20issue.%29%0A" target="_blank" rel="noopener">Report it on GitHub ↗</a></span><span class="sep" aria-hidden="true"> · </span><span>Questions: <a href="mailto:contact@hostwatch.tech">contact@hostwatch.tech</a></span><span class="sep" aria-hidden="true"> · </span><span>Security reports: <a href="mailto:security@hostwatch.tech">security@hostwatch.tech</a></span></p>
  <p><a href="../">Home</a> · <a href="{repo}" target="_blank" rel="noopener">GitHub</a> ·
  <a href="{repo}/blob/main/CHANGELOG.md" target="_blank" rel="noopener">Changelog</a></p></footer>
<script>
  // Every section of every page (for search), which page each section id is on, and this page.
  const DOCS_INDEX = {index_json};
  const DOCS_IDS = {ids_json};
  const DOCS_PAGE = "{page}";
  // A link to a section on another page (old single-page links like docs/#firewall): go to its page.
  (() => {{
    const id = decodeURIComponent(location.hash.slice(1));
    if (id && !document.getElementById(id) && DOCS_IDS[id] && DOCS_IDS[id] !== DOCS_PAGE)
      location.replace(DOCS_IDS[id] + location.search + "#" + id);
  }})();
  function reveal(id) {{
    const el = id && document.getElementById(id);
    const d = el && el.closest("details.more");
    if (d) d.open = true;
  }}
  addEventListener("hashchange", () => reveal(decodeURIComponent(location.hash.slice(1))));
  if (location.hash) reveal(decodeURIComponent(location.hash.slice(1)));
  const phone = matchMedia("(max-width: 900px)");
  const toc = document.querySelector(".contents");
  if (phone.matches) toc.open = false;
  // Back to top: only once you've scrolled down a screen or so.
  const totop = document.querySelector(".totop");
  addEventListener("scroll", () => totop.classList.toggle("shown", scrollY > 900), {{ passive: true }});
  // The open chapter's sections can be hidden and shown again: a tap anywhere on its row (name or arrow).
  function foldChapter(li) {{
    const folded = li.classList.toggle("folded"), b = li.querySelector(":scope > .fold");
    if (b) {{ b.setAttribute("aria-expanded", String(!folded));
             b.setAttribute("aria-label", folded ? "Show this chapter's sections" : "Hide this chapter's sections"); }}
  }}
  document.querySelectorAll("nav.toc .contents > ol > li.here").forEach(li => {{
    for (const el of li.querySelectorAll(":scope > a, :scope > .fold")) el.addEventListener("click", e => {{
      e.preventDefault(); e.stopPropagation(); foldChapter(li);
    }});
  }});
  document.querySelector("nav.toc").addEventListener("click", e => {{
    if (phone.matches && e.target.closest("a")) toc.open = false;
  }});
  // Search: an index of every section (h2-h4 and the text under it), ranked results with excerpts, keyboard driven.
  const main = document.querySelector("main"), q = document.querySelector(".q");
  const results = document.querySelector(".results"), contents = document.querySelector(".contents");
  const heads = [...main.querySelectorAll("h2[id], h3[id], h4[id]")];
  const level = h => +h.tagName[1];
  const index = DOCS_INDEX;
  const esc = t => t.replace(/[&<>"]/g, c => ({{"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}})[c]);
  // Case-insensitive highlighting without regular expressions: find each term, wrap it.
  function spans(t, terms) {{
    const low = t.toLowerCase(), out = [];
    for (const w of terms) {{ let k = low.indexOf(w); while (k >= 0) {{ out.push([k, k + w.length]); k = low.indexOf(w, k + w.length); }} }}
    out.sort((a, b) => a[0] - b[0]);
    const merged = [];
    for (const r of out) {{ if (merged.length && r[0] <= merged[merged.length - 1][1]) merged[merged.length - 1][1] = Math.max(merged[merged.length - 1][1], r[1]); else merged.push(r); }}
    return merged;
  }}
  function marked(t, terms, cls) {{
    let html = "", at = 0;
    for (const [a, b] of spans(t, terms)) {{ html += esc(t.slice(at, a)) + "<mark" + (cls ? ' class="' + cls + '"' : "") + ">" + esc(t.slice(a, b)) + "</mark>"; at = b; }}
    return html + esc(t.slice(at));
  }}
  const mark = (t, terms) => marked(t, terms, "");
  let sel = 0, shown = [];

  function search(raw) {{
    const terms = raw.toLowerCase().split(/\s+/).filter(Boolean);
    if (!terms.length) {{ results.hidden = true; contents.hidden = false; return; }}
    shown = index.map(e => {{
      const t = e.title.toLowerCase(), x = e.text.toLowerCase();
      let score = 0;
      for (const w of terms) {{
        const inT = t.includes(w), inX = x.includes(w);
        if (!inT && !inX) return null;
        score += (inT ? 10 : 0) + (t.startsWith(w) ? 5 : 0) + Math.min(x.split(w).length - 1, 8);
      }}
      return {{ e, score }};
    }}).filter(Boolean).sort((a, b) => b.score - a.score).slice(0, 20);
    sel = 0;
    contents.hidden = true; results.hidden = false;
    if (!shown.length) {{ results.innerHTML = '<div class="empty">Nothing matches “' + esc(raw) + '”.</div>'; return; }}
    results.innerHTML = '<div class="count">' + shown.length + (shown.length === 20 ? "+" : "") + " results</div>" + shown.map((r, i) => {{
      const x = r.e.text, lx = x.toLowerCase(), at = Math.max(0, Math.min(...terms.map(w => {{ const k = lx.indexOf(w); return k < 0 ? 1e9 : k; }})));
      const start = at === 1e9 ? 0 : Math.max(0, at - 50), snip = (start ? "…" : "") + x.slice(start, start + 150) + (x.length > start + 150 ? "…" : "");
      return '<a href="' + (r.e.page === DOCS_PAGE ? "" : r.e.page) + '#' + r.e.id + '" data-i="' + i + '" class="' + (i ? "" : "sel") + '" role="option">' +
             (r.e.group ? '<span class="where">' + esc(r.e.group) + '</span>' : "") +
             '<span class="title">' + mark(r.e.title, terms) + '</span><span class="snip">' + mark(snip, terms) + "</span></a>";
    }}).join("");
  }}

  // Jumping to a result highlights the words in that section until the next search.
  function clearHits() {{ main.querySelectorAll("mark.hit").forEach(m => m.replaceWith(document.createTextNode(m.textContent))); main.normalize(); }}
  function highlight(id, terms) {{
    clearHits();
    const h = document.getElementById(id); if (!h || !terms.length) return;
    let n = h.nextElementSibling; const blocks = [h];
    while (n && !(/^H[2-4]$/.test(n.tagName) && level(n) <= level(h))) {{ blocks.push(n); n = n.nextElementSibling; }}
    blocks.forEach(b => {{
      const walk = document.createTreeWalker(b, NodeFilter.SHOW_TEXT), nodes = [];
      while (walk.nextNode()) nodes.push(walk.currentNode);
      nodes.forEach(t => {{
        if (!spans(t.nodeValue, terms).length) return;
        const span = document.createElement("span");
        span.innerHTML = marked(t.nodeValue, terms, "hit");
        t.replaceWith(...span.childNodes);
      }});
    }});
    // A match inside a folded Details: unfold it so you see what you searched for.
    main.querySelectorAll("mark.hit").forEach(m => {{ const d = m.closest("details.more"); if (d) d.open = true; }});
  }}
  function open(i) {{
    const r = shown[i]; if (!r) return;
    if (r.e.page !== DOCS_PAGE) {{ location.href = r.e.page + "?q=" + encodeURIComponent(q.value) + "#" + r.e.id; return; }}
    reveal(r.e.id);
    const terms = q.value.toLowerCase().split(/\s+/).filter(Boolean);
    location.hash = r.e.id; highlight(r.e.id, terms);
  }}
  // Arrived from a search on another page: highlight the words there.
  (() => {{
    const words = new URLSearchParams(location.search).get("q"), id = decodeURIComponent(location.hash.slice(1));
    if (words && id) {{ reveal(id); highlight(id, words.toLowerCase().split(/\s+/).filter(Boolean)); }}
  }})();
  q.addEventListener("input", () => search(q.value));
  q.addEventListener("keydown", e => {{
    const items = [...results.querySelectorAll("a")];
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {{
      e.preventDefault(); if (!items.length) return;
      sel = (sel + (e.key === "ArrowDown" ? 1 : items.length - 1)) % items.length;
      items.forEach((a, k) => a.classList.toggle("sel", k === sel)); items[sel].scrollIntoView({{ block: "nearest" }});
    }} else if (e.key === "Enter") {{ e.preventDefault(); open(sel); }}
    else if (e.key === "Escape") {{ q.value = ""; search(""); clearHits(); q.blur(); }}
  }});
  results.addEventListener("click", e => {{ const a = e.target.closest("a"); if (!a) return; e.preventDefault(); open(+a.dataset.i); }});
  document.addEventListener("keydown", e => {{
    if ((e.key === "/" && document.activeElement !== q) || (e.key === "k" && (e.metaKey || e.ctrlKey))) {{ e.preventDefault(); q.focus(); q.select(); }}
  }});
  // Highlight the section being read; expand its chapter on the left and list its sections on the right.
  const links = new Map([...document.querySelectorAll('.contents a[href^="#"]')].map(a => [a.getAttribute("href").slice(1), a]));
  const onpage = document.querySelector(".onpage ol");
  let chapterShown = null;
  function showChapter(section) {{
    if (section === chapterShown) return;
    chapterShown = section;
    const h2 = section && section.querySelector("h2[id]");
    document.querySelectorAll(".contents li.current").forEach(li => li.classList.remove("current"));
    const top = h2 && links.get(h2.id);
    if (top) top.closest("li").classList.add("current");
    onpage.innerHTML = "";
    if (!section) return;
    section.querySelectorAll("h3[id], h4[id]").forEach(h => {{
      const a = document.createElement("a");
      a.href = "#" + h.id;
      a.textContent = h.textContent.replace(/^#/, "");
      if (h.tagName === "H4") a.className = "sub";
      const li = document.createElement("li"); li.append(a); onpage.append(li);
    }});
  }}
  // The current section is the last heading scrolled past (just below the header): always one, or none at the top.
  let current;                                               // undefined: the first track() always draws
  // A section you picked stays selected while the page glides there (and if it's too near the end to reach the top).
  let picked = null, pickTimer = 0;
  function pick(id) {{
    reveal(id);
    picked = document.getElementById(id);
    landedAt = null;
    clearTimeout(pickTimer);
    pickTimer = setTimeout(release, 1500);                  // in case the browser sends no "scrollend"
    current = null; track();
  }}
  function release() {{
    if (!picked) return;
    const r = picked.getBoundingClientRect();
    const atEnd = innerHeight + scrollY >= document.documentElement.scrollHeight - 4;
    // Still where you asked to be: keep it until you scroll on yourself.
    if (atEnd || (r.top >= 0 && r.top < innerHeight / 2)) {{ landedAt = scrollY; return; }}
    unpick();
  }}
  // Then tracking resumes as soon as you scroll on, by any means (wheel, keys, scrollbar, touch).
  let landedAt = null;
  addEventListener("scroll", () => {{ if (landedAt !== null && Math.abs(scrollY - landedAt) > 40) unpick(); }}, {{ passive: true }});
  function unpick() {{ picked = null; landedAt = null; current = null; track(); }}
  addEventListener("scrollend", () => {{ if (picked) {{ clearTimeout(pickTimer); release(); }} }});
  document.addEventListener("click", e => {{
    const a = e.target.closest('nav.toc a[href^="#"], .onpage a, .pager a');
    if (a && !a.closest(".results")) pick(a.getAttribute("href").slice(1));
  }});
  function track() {{
    let h = picked;
    // Headings inside a folded Details aren't on screen (no box): skip them.
    if (!h) for (const x of heads) {{ if (!x.getClientRects().length) continue; if (x.getBoundingClientRect().top <= 140) h = x; else break; }}
    if (h === current) return;
    current = h;
    links.forEach(a => a.classList.remove("active"));
    let a = h && links.get(h.id);
    for (let i = h ? heads.indexOf(h) - 1 : -1; !a && i >= 0; i--) a = links.get(heads[i].id);   // a feature: its group
    if (a) a.classList.add("active");
    document.querySelectorAll(".contents li.open").forEach(li => li.classList.remove("open"));
    for (let li = a && a.closest("li"); li; li = li.parentElement.closest("li")) li.classList.add("open");
    showChapter(h ? h.closest("section.chapter:not(.intro)") : main.querySelector("section.chapter"));
    onpage.querySelectorAll("a").forEach(x => x.classList.toggle("active", !!h && x.getAttribute("href") === "#" + h.id));
  }}
  let ticking = false;
  addEventListener("scroll", () => {{ if (!ticking) {{ ticking = true; requestAnimationFrame(() => {{ ticking = false; track(); }}); }} }}, {{ passive: true }});
  addEventListener("load", track); track();

  // Reading progress under the header.
  const bar = document.querySelector(".progress");
  const progress = () => {{
    const max = document.documentElement.scrollHeight - innerHeight;
    bar.style.width = (max > 0 ? Math.min(100, scrollY / max * 100) : 0) + "%";
  }};
  addEventListener("scroll", progress, {{ passive: true }}); progress();

  // Copy buttons on code, and the # next to a heading copies its link.
  main.querySelectorAll("pre").forEach(pre => {{
    const b = document.createElement("button");
    b.className = "copy"; b.type = "button"; b.textContent = "Copy";
    b.addEventListener("click", async () => {{
      try {{ await navigator.clipboard.writeText(pre.querySelector("code")?.innerText ?? pre.innerText); b.textContent = "Copied"; }}
      catch {{ b.textContent = "Select and ⌘C"; }}
      setTimeout(() => b.textContent = "Copy", 1500);
    }});
    pre.append(b);
  }});
  main.addEventListener("click", async e => {{
    const a = e.target.closest("a.anchor"); if (!a) return;
    e.preventDefault();
    history.replaceState(null, "", a.getAttribute("href"));
    a.closest("h2, h3, h4").scrollIntoView({{ behavior: "smooth" }});
    try {{ await navigator.clipboard.writeText(location.href); a.classList.add("copied"); setTimeout(() => a.classList.remove("copied"), 1400); }} catch {{}}
  }});
</script>
</body>
</html>
"""


def search_entries(html_body, page, chapter):
    """Every h3/h4 of a page with the plain text under it (to the next heading) and its group, for search."""
    out = []
    marks = list(re.finditer(r'<h([234]) id="([^"]+)">(?:<a class="anchor"[^>]*>#</a>)?(.*?)</h\1>', html_body))
    group3 = chapter
    for k, m in enumerate(marks):
        level, sid, title = int(m.group(1)), m.group(2), re.sub(r"<[^>]+>", "", m.group(3))
        end = marks[k + 1].start() if k + 1 < len(marks) else len(html_body)
        text = html.unescape(re.sub(r"<[^>]+>", " ", html_body[m.end():end]))
        text = re.sub(r"\s+", " ", text.replace("Details", " ", 1) if "<details" in html_body[m.end():end] else text).strip()
        title = html.unescape(title).strip()
        if level == 3:
            group = chapter
            group3 = title
        elif level == 4:
            group = group3
        else:
            continue
        out.append({"id": sid, "title": title, "group": group, "text": text, "page": page})
    return out


def menu(chapters, here):
    """Chapters (numbered); the one on this page expanded with its sections (and a group's features)."""
    out = ["<ol>"]
    for n, ch in enumerate(chapters, 1):
        current = ch["page"] == here
        href = f'#{ch["id"]}' if current else ch["page"]
        cls = ' class="here"' if current else ""
        fold = ('<button class="fold" type="button" aria-expanded="true" aria-label="Hide this chapter\'s sections"></button>'
                if current else "")
        out.append(f'<li{cls}><a href="{href}"><span class="n">{n:02d}</span>{ch["title"]}</a>{fold}')
        if current:
            inner = toc_html([t for t in ch["toc"] if t[0] > 2])
            out.append(inner)
        out.append("</li>")
    out.append("</ol>")
    return "".join(out)


def main():
    files = sorted(CHAPTERS.glob("[0-9][0-9]-*.md"))
    PAGES.clear()
    for f in files:
        PAGES[f.name] = re.sub(r"^\d\d-", "", f.stem) + ".html"
    mark = (ROOT / "docs" / "images" / "site" / "mark.svg").read_text()
    inner = mark[mark.index("<g transform"):mark.rindex("</g>") + 4] if "<g transform" in mark else ""
    mark_svg = f'<svg viewBox="0 0 24 24" fill="none" aria-hidden="true">{inner}</svg>'

    seen, chapters = {}, []
    for f in files:
        body, toc = convert(f.read_text(), seen)
        body = heading_icons(kind_icons(body))
        title = next(t for lvl, _, t in toc if lvl == 2)
        sid = next(i for lvl, i, _ in toc if lvl == 2)
        chapters.append({"file": f.name, "page": PAGES[f.name], "title": title, "id": sid, "toc": toc, "body": body})
    index = [e for ch in chapters for e in search_entries(ch["body"], ch["page"], ch["title"])]
    ids = {i: ch["page"] for ch in chapters for _, i, _ in ch["toc"]}
    common = dict(site=SITE, repo=REPO, mark=mark_svg, index_json=json.dumps(index, ensure_ascii=False).replace("</", "<\\/"),
                  ids_json=json.dumps(ids))
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # The overview: the front page's intro, and a card per chapter.
    front = SRC.read_text()
    intro_md, _, listing = front.partition("## Chapters")
    intro_html, _ = convert(intro_md)
    blurbs = dict(re.findall(r"\*\*\[([^\]]+)\]\([^)]+\)\*\*: (.+)", listing))
    sentence = lambda t: (t[:1].upper() + t[1:]) if t else t      # "what you need…" → "What you need…"
    cards = "".join(f'<a href="{ch["page"]}"><small>{group_icon(ch["id"])}{n:02d}</small><b>{ch["title"]}</b><span>{html.escape(sentence(blurbs.get(ch["title"], "")))}</span></a>'
                    for n, ch in enumerate(chapters, 1))
    hero = ('<div class="hero"><div class="label"><span>Docs</span></div>'
            '<h1>How Hostwatch works. <span class="quiet">Every feature, setting and rule.</span></h1>'
            "<p>Built from the same reference that lives in the repository, so it's always current. New here? Start with "
            f'<a href="{chapters[0]["page"]}">{chapters[0]["title"]}</a>, then read on in order.</p></div>')
    (OUT_DIR / "index.html").write_text(PAGE.format(
        **common, title="Hostwatch docs: every feature, setting and rule", edit_url=f"{REPO}/blob/main/docs/reference.md",
        page="index.html", toc=menu(chapters, None), hero=hero,
        body=f'<section class="chapter intro">{intro_html}<div class="cards">{cards}</div></section>'))

    # One page per chapter.
    for n, ch in enumerate(chapters):
        prev = (chapters[n - 1]["page"], chapters[n - 1]["title"]) if n > 0 else ("index.html", "Docs overview")
        nxt = (chapters[n + 1]["page"], chapters[n + 1]["title"]) if n + 1 < len(chapters) else None
        hero = f'<div class="hero slim"><div class="label"><span>Docs · Chapter {n + 1:02d}</span></div></div>'
        (OUT_DIR / ch["page"]).write_text(PAGE.format(
            **common, title=f'{ch["title"]} · Hostwatch docs', edit_url=f'{REPO}/blob/main/docs/reference/{ch["file"]}',
            page=ch["page"], toc=menu(chapters, ch["page"]), hero=hero, body=chapter_section(ch["body"], prev, nxt)))
    print(f"wrote docs/docs/index.html and {len(chapters)} chapter pages ({len(index)} sections in search)")


if __name__ == "__main__":
    sys.exit(main())
