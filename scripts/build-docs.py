#!/usr/bin/env python3
"""Builds the documentation page of the website from docs/reference.md.

    python3 scripts/build-docs.py        (run from the repo root; writes docs/docs/index.html)

The reference stays the one source: GitHub shows the markdown, the website shows this page, in the main site's
style (fonts, colours, spacing). Only the markdown the reference uses is supported: headings, paragraphs, nested
and numbered lists, tables, fenced code, inline code, bold, italic and links. No dependencies.
"""
import html
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "reference.md"
OUT = ROOT / "docs" / "docs" / "index.html"
SITE = "https://everythings-gonna-be-alright.github.io/Hostwatch/"
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
        if url.endswith(".md") or ".md#" in url:          # links to other repo files go to GitHub
            url = f"{REPO}/blob/main/docs/{url}" if not url.startswith("../") else f"{REPO}/blob/main/{url[3:]}"
        external = url.startswith("http")
        attrs = ' target="_blank" rel="noopener"' if external else ""
        return f'<a href="{html.escape(url)}"{attrs}>{label}</a>'

    text = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", link, text)
    text = re.sub(r"&lt;(https?://[^\s&]+)&gt;", r'<a href="\1" target="_blank" rel="noopener">\1</a>', text)   # <https://…> autolinks
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"(?<![\w*])\*([^*\n]+)\*(?![\w*])", r"<i>\1</i>", text)
    text = re.sub(r"\x00(\d+)\x00", lambda m: codes[int(m.group(1))], text)
    return text


def convert(md):
    lines = md.split("\n")
    out, toc = [], []
    i, n = 0, len(lines)
    para = []
    seen = {}

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


def toc_html(toc):
    parts, open_sub, num = ["<ol>"], False, 0
    for level, sid, text in toc:
        if level == 2:
            if open_sub:
                parts.append("</ol></li>")
                open_sub = False
            elif num:
                parts.append("</li>")
            num += 1
            parts.append(f'<li><a href="#{sid}"><span class="n">{num:02d}</span>{html.escape(text)}</a>')
        elif level == 3:
            if not open_sub:
                parts.append("<ol>")
                open_sub = True
            parts.append(f'<li><a href="#{sid}">{html.escape(text)}</a></li>')
    parts.append("</ol></li>" if open_sub else "</li>")
    parts.append("</ol>")
    return "".join(parts)


def sections(body):
    """Wrap each h2 and what follows in a <section>, so the filter can hide whole chapters."""
    chunks = re.split(r'(?=<h2 id=")', body)
    intro, rest = chunks[0], chunks[1:]
    out = [f'<section class="chapter intro">{intro}</section>'] if intro.strip() else []
    for c in rest:
        out.append(f'<section class="chapter">{c}</section>')
    return "\n".join(out)


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hostwatch docs: every feature, setting and rule</title>
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

  .layout {{ max-width: 1240px; margin: 0 auto; padding: 0 24px; display: grid; grid-template-columns: 280px minmax(0, 1fr); gap: 56px; }}
  nav.toc {{ position: sticky; top: 64px; align-self: start; max-height: calc(100vh - 64px); overflow: auto; padding: 28px 8px 40px 0; }}
  .filter {{ width: 100%; height: 38px; padding: 0 12px; border-radius: var(--r-control); border: 1px solid var(--line-strong); background: var(--bg-raise);
            color: var(--text); font: 400 14px var(--sans); margin-bottom: 18px; }}
  .filter::placeholder {{ color: var(--dim); }}
  nav.toc ol {{ list-style: none; margin: 0; padding: 0; }}
  nav.toc ol ol {{ margin: 2px 0 6px 30px; }}
  nav.toc a {{ display: flex; gap: 10px; padding: 5px 8px; border-radius: 8px; color: var(--muted); text-decoration: none; font-size: 14px; line-height: 1.4; }}
  nav.toc a:hover {{ color: var(--text); background: rgba(255,255,255,0.03); }}
  nav.toc a.active {{ color: var(--text); background: rgba(255,255,255,0.05); }}
  nav.toc .n {{ font: 500 11px/1.9 var(--mono); color: var(--dim); min-width: 18px; }}
  nav.toc li.hidden {{ display: none; }}

  main {{ padding: 40px 0 120px; min-width: 0; }}
  .hero {{ padding: 24px 0 40px; border-bottom: 1px solid var(--line); margin-bottom: 8px; }}
  .label {{ font: 500 13px var(--mono); color: var(--muted); display: flex; gap: 10px; align-items: center; }}
  .label::after {{ content: ""; flex: 0 0 40px; height: 1px; background: var(--line-strong); }}
  h1 {{ font-weight: 500; font-size: clamp(36px, 5vw, 56px); line-height: 1.04; letter-spacing: -0.035em; margin: 18px 0 14px; }}
  h1 .quiet {{ color: var(--dim); }}
  .hero p {{ color: var(--muted); font-size: 17px; max-width: 640px; margin: 0; }}
  .chapter {{ border-bottom: 1px solid var(--line); padding: 8px 0 32px; }}
  .chapter.hidden {{ display: none; }}
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
  code {{ font: 13px var(--mono); background: rgba(255,255,255,0.06); padding: 1px 6px; border-radius: 6px; color: #e6e8eb; }}
  pre {{ background: var(--bg-raise); border: 1px solid var(--line); border-radius: var(--r-control); padding: 16px 18px; overflow: auto; }}
  pre code {{ background: none; padding: 0; font-size: 13px; line-height: 1.6; }}
  .table {{ overflow-x: auto; margin: 16px 0; }}
  table {{ border-collapse: collapse; font-size: 14px; min-width: 60%; }}
  th, td {{ text-align: left; padding: 9px 16px 9px 0; border-bottom: 1px solid var(--line); vertical-align: top; color: #c9ccd1; }}
  th {{ font: 500 12px var(--mono); color: var(--dim); }}
  .none {{ display: none; color: var(--muted); padding: 40px 0; }}
  footer {{ border-top: 1px solid var(--line); padding: 32px 24px 48px; color: var(--dim); font-size: 13px; text-align: center; }}
  footer a {{ color: var(--muted); }}
  @media (max-width: 900px) {{
    .layout {{ grid-template-columns: 1fr; gap: 0; }}
    nav.toc {{ position: static; max-height: none; border-bottom: 1px solid var(--line); padding-bottom: 20px; }}
    .anchor {{ display: none; }}
    .crumb {{ display: none; }}
  }}
  @media (prefers-reduced-motion: reduce) {{ html {{ scroll-behavior: auto; }} }}
</style>
</head>
<body>
<header class="top"><div class="in">
  <a class="brand" href="../"><span class="tile">{mark}</span><span>Host<span class="soft">watch</span></span></a>
  <span class="crumb">/ docs</span>
  <div class="right">
    <a class="btn" href="{repo}/blob/main/docs/reference.md" target="_blank" rel="noopener">Edit on GitHub</a>
    <a class="btn light" href="{repo}/releases/latest">Download</a>
  </div>
</div></header>
<div class="layout">
  <nav class="toc" aria-label="Contents">
    <input class="filter" type="search" placeholder="Filter the docs" aria-label="Filter the docs">
    {toc}
  </nav>
  <main>
    <div class="hero">
      <div class="label"><span>Docs</span></div>
      <h1>How Hostwatch works. <span class="quiet">Every feature, setting and rule.</span></h1>
      <p>Built from the same reference that lives in the repository, so it's always current. New here? Start with the
        <a href="../#when">install steps</a>, then read on in order.</p>
    </div>
    {body}
    <p class="none">Nothing matches that filter.</p>
  </main>
</div>
<footer>Hostwatch · MIT license · <a href="../">Home</a> · <a href="{repo}" target="_blank" rel="noopener">GitHub</a> ·
  <a href="{repo}/blob/main/CHANGELOG.md" target="_blank" rel="noopener">Changelog</a></footer>
<script>
  // Filter: hide chapters (and their entries) that don't mention the text.
  const box = document.querySelector(".filter"), chapters = [...document.querySelectorAll(".chapter")];
  const entries = [...document.querySelectorAll("nav.toc > ol > li")], none = document.querySelector(".none");
  box.addEventListener("input", () => {{
    const q = box.value.trim().toLowerCase(); let shown = 0;
    chapters.forEach(c => {{
      const hit = !q || c.textContent.toLowerCase().includes(q);
      c.classList.toggle("hidden", !hit); if (hit) shown++;
      const h = c.querySelector("h2"); if (!h) return;
      const li = entries.find(l => l.querySelector("a").getAttribute("href") === "#" + h.id);
      if (li) li.classList.toggle("hidden", !hit);
    }});
    none.style.display = shown ? "none" : "block";
  }});
  // Highlight the section being read.
  const links = new Map([...document.querySelectorAll("nav.toc a")].map(a => [a.getAttribute("href").slice(1), a]));
  const seen = new IntersectionObserver(es => es.forEach(e => {{
    if (!e.isIntersecting) return;
    links.forEach(a => a.classList.remove("active"));
    const a = links.get(e.target.id); if (a) a.classList.add("active");
  }}), {{ rootMargin: "-80px 0px -70% 0px" }});
  document.querySelectorAll("main h2[id], main h3[id]").forEach(h => seen.observe(h));
</script>
</body>
</html>
"""


def main():
    md = SRC.read_text()
    body, toc = convert(md)
    mark = (ROOT / "docs" / "images" / "site" / "mark.svg").read_text()
    inner = mark[mark.index("<g transform"):mark.rindex("</g>") + 4] if "<g transform" in mark else ""
    mark_svg = f'<svg viewBox="0 0 24 24" fill="none" aria-hidden="true">{inner}</svg>'
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(PAGE.format(site=SITE, repo=REPO, mark=mark_svg, toc=toc_html(toc), body=sections(body)))
    print(f"wrote {OUT.relative_to(ROOT)} ({len(toc)} headings)")


if __name__ == "__main__":
    sys.exit(main())
