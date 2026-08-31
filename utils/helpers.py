"""
Helper utilities for formatting, cyber risk badge rendering, and text processing in IntelAssist AI.
"""

import time
import math
import hashlib
from typing import List, Dict, Any

def format_file_size(size_in_bytes: int) -> str:
    """Format bytes into a human readable file size string."""
    if size_in_bytes <= 0:
        return "0 B"
    size_names = ("B", "KB", "MB", "GB", "TB")
    i = int(math.floor(math.log(size_in_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_in_bytes / p, 2)
    return f"{s} {size_names[i]}"

def get_file_icon(file_extension: str) -> str:
    """Return an appropriate modern icon for file types."""
    ext = file_extension.lower().strip()
    if ext == ".pdf":
        return "📕"
    elif ext in [".doc", ".docx"]:
        return "📘"
    elif ext in [".txt", ".md"]:
        return "📄"
    elif ext == ".log":
        return "📋"
    elif ext == ".csv":
        return "📊"
    elif ext == ".json":
        return "📦"
    return "📁"

def get_ioc_icon(ioc_type: str) -> str:
    """Return an appropriate cyber indicator icon."""
    t = ioc_type.lower()
    if "ip" in t:
        return "🌐"
    elif "domain" in t:
        return "🔗"
    elif "url" in t:
        return "🌍"
    elif "hash" in t or "sha" in t or "md5" in t:
        return "🔑"
    elif "cve" in t:
        return "🛡️"
    elif "file" in t:
        return "💾"
    elif "email" in t:
        return "✉️"
    elif "mitre" in t:
        return "🎯"
    return "🏷️"

def generate_doc_id(content_or_filename: str) -> str:
    """Generate a stable short ID from a document string."""
    return hashlib.md5(content_or_filename.encode("utf-8")).hexdigest()[:10]

def highlight_keywords(text: str, query: str, max_length: int = 350) -> str:
    """Highlight query terms in a snippet and truncate cleanly."""
    if not text:
        return ""

    words = [w.strip() for w in query.lower().split() if len(w.strip()) > 2]

    first_idx = len(text)
    for word in words:
        pos = text.lower().find(word)
        if 0 <= pos < first_idx:
            first_idx = pos

    start = max(0, first_idx - 60)
    end = min(len(text), start + max_length)
    snippet = text[start:end]

    if start > 0:
        snippet = "..." + snippet
    if end < len(text):
        snippet = snippet + "..."

    return snippet

def get_risk_badge_html(risk_level: str) -> str:
    """Return a stylized cybersecurity risk badge HTML."""
    lvl = (risk_level or "Low").capitalize()
    if lvl == "Critical":
        color = "#ef4444"
        bg = "rgba(239, 68, 68, 0.18)"
        border = "rgba(239, 68, 68, 0.45)"
        icon = "🚨"
    elif lvl == "High":
        color = "#f97316"
        bg = "rgba(249, 115, 22, 0.18)"
        border = "rgba(249, 115, 22, 0.45)"
        icon = "🔥"
    elif lvl == "Elevated":
        color = "#f59e0b"
        bg = "rgba(245, 158, 11, 0.18)"
        border = "rgba(245, 158, 11, 0.45)"
        icon = "⚠️"
    elif lvl == "Medium":
        color = "#38bdf8"
        bg = "rgba(56, 189, 248, 0.18)"
        border = "rgba(56, 189, 248, 0.45)"
        icon = "🔍"
    else:
        color = "#10b981"
        bg = "rgba(16, 185, 129, 0.18)"
        border = "rgba(16, 185, 129, 0.45)"
        icon = "🛡️"

    return f"""<span style="display:inline-flex; align-items:center; gap:4px; font-weight:700; font-size:0.75rem; padding:2px 8px; border-radius:6px; background:{bg}; color:{color}; border:1px solid {border}; font-family:'JetBrains Mono', monospace;">
        <span>{icon}</span> {lvl}
    </span>"""

def get_relevance_badge_html(score: float) -> str:
    """Return calibrated Retrieval Relevance badge HTML."""
    pct = int(min(100, max(0, score * 100)))
    if pct >= 75:
        emoji = "🟢"
        label = "Strong match"
        color = "#10b981"
        bg = "rgba(16, 185, 129, 0.15)"
        border = "rgba(16, 185, 129, 0.35)"
    elif pct >= 55:
        emoji = "🟡"
        label = "Moderate match"
        color = "#f59e0b"
        bg = "rgba(245, 158, 11, 0.15)"
        border = "rgba(245, 158, 11, 0.35)"
    else:
        emoji = "🔴"
        label = "Weak match"
        color = "#ef4444"
        bg = "rgba(239, 68, 68, 0.15)"
        border = "rgba(239, 68, 68, 0.35)"

    return f"""<span title="{pct}% Retrieval Relevance ({label})" style="display:inline-flex; align-items:center; gap:5px; font-weight:600; font-size:0.75rem; padding:3px 10px; border-radius:9999px; background:{bg}; color:{color}; border:1px solid {border};">
        <span>{emoji}</span> {pct}% Relevance ({label})
    </span>"""
