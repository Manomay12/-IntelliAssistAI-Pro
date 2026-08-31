"""
Cross-Source Threat Correlation & Relationship Graph Engine for IntelAssist AI.
Correlates indicators (IPs, Domains, Hashes, URLs, CVEs) across threat reports, security logs,
and forensic artifacts to construct interactive entity relationship graphs and context summaries.
"""

import math
from typing import List, Dict, Any, Optional, Set, Tuple
import plotly.graph_objects as go

class ThreatCorrelator:
    """Correlates security indicators across heterogeneous data sources and generates network graphs."""

    @classmethod
    def correlate_indicator(
        cls,
        target_indicator: str,
        document_registry: Dict[str, Any],
        log_results: Optional[List[Dict[str, Any]]] = None,
        all_extracted_iocs: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Cross-correlate a single indicator across all indexed documents, parsed logs, and extracted IOCs.
        """
        target = target_indicator.strip().lower()
        if not target:
            return {"found": False, "target": target_indicator, "relationships": []}

        matched_docs: List[Dict[str, Any]] = []
        matched_logs: List[Dict[str, Any]] = []
        co_occurring_iocs: List[Dict[str, Any]] = []
        contexts: List[str] = []

        # 1. Search in Document Registry (Threat Reports & PDFs)
        for fname, dinfo in document_registry.items():
            full_text = dinfo.get("full_text", "")
            if target in full_text.lower():
                # Extract snippet
                idx = full_text.lower().find(target)
                start = max(0, idx - 100)
                end = min(len(full_text), idx + len(target) + 100)
                snippet = full_text[start:end].replace("\n", " ").strip()
                contexts.append(snippet)

                matched_docs.append({
                    "filename": fname,
                    "type": "Threat Report / Document",
                    "snippet": snippet,
                    "pages": dinfo.get("total_pages", 1)
                })

        # 2. Search in Log Results
        logs_to_search = log_results or []
        for log_data in logs_to_search:
            fname = log_data.get("filename", "Log File")
            events = log_data.get("events", [])
            alerts = log_data.get("alerts", [])

            # Check matching events
            matching_events = [
                e for e in events
                if target in str(e.get("source_ip", "")).lower() or target in str(e.get("raw", "")).lower()
            ]
            if matching_events:
                matched_logs.append({
                    "filename": fname,
                    "type": "Security Log",
                    "event_count": len(matching_events),
                    "first_event": matching_events[0].get("description", ""),
                    "events": matching_events[:5]
                })

            # Check matching alerts
            for a in alerts:
                if target in str(a.get("source_ip", "")).lower() or target in str(a.get("reason", "")).lower():
                    contexts.append(f"Alert: {a.get('title')} ({a.get('reason')})")

        # 3. Find Co-occurring IOCs across matching documents
        matching_sources = set(d["filename"] for d in matched_docs)
        if all_extracted_iocs and matching_sources:
            for ioc in all_extracted_iocs:
                ind = ioc.get("indicator", "").lower()
                if ind != target:
                    ioc_sources = set(ioc.get("sources", []))
                    overlap = matching_sources.intersection(ioc_sources)
                    if overlap:
                        co_occurring_iocs.append({
                            "indicator": ioc.get("indicator"),
                            "type": ioc.get("type"),
                            "risk_level": ioc.get("risk_level", "Medium"),
                            "shared_sources": list(overlap)
                        })

        total_correlations = len(matched_docs) + len(matched_logs) + len(co_occurring_iocs)
        is_found = total_correlations > 0

        return {
            "found": is_found,
            "target": target_indicator,
            "total_correlations": total_correlations,
            "matched_docs": matched_docs,
            "matched_logs": matched_logs,
            "co_occurring_iocs": co_occurring_iocs[:10],
            "contexts": contexts[:8]
        }

    @classmethod
    def generate_relationship_graph(
        cls,
        target_indicator: str,
        correlation_data: Dict[str, Any]
    ) -> go.Figure:
        """
        Build an interactive 2D node-link cybersecurity relationship graph using Plotly.
        """
        nodes: List[Dict[str, Any]] = []
        edges: List[Tuple[int, int]] = []

        # Central Target Node (Index 0)
        nodes.append({
            "id": 0,
            "label": f"🎯 {target_indicator}",
            "type": "Target Indicator",
            "color": "#ef4444",
            "size": 32,
            "hover": f"Investigated Indicator: {target_indicator}"
        })

        current_idx = 1

        # 1. Add Matched Document Nodes
        for doc in correlation_data.get("matched_docs", []):
            nodes.append({
                "id": current_idx,
                "label": f"📄 {doc['filename'][:18]}...",
                "type": "Threat Report",
                "color": "#38bdf8",
                "size": 22,
                "hover": f"Document: {doc['filename']}<br>Pages: {doc.get('pages', 1)}"
            })
            edges.append((0, current_idx))
            current_idx += 1

        # 2. Add Matched Log Nodes
        for log in correlation_data.get("matched_logs", []):
            nodes.append({
                "id": current_idx,
                "label": f"📋 {log['filename'][:18]}...",
                "type": "Security Log",
                "color": "#f59e0b",
                "size": 22,
                "hover": f"Log: {log['filename']}<br>Events: {log.get('event_count', 1)}"
            })
            edges.append((0, current_idx))
            current_idx += 1

        # 3. Add Co-occurring IOC Nodes
        for ioc in correlation_data.get("co_occurring_iocs", [])[:8]:
            color = "#ef4444" if ioc.get("risk_level") == "Critical" else "#a855f7"
            nodes.append({
                "id": current_idx,
                "label": f"🏷️ {ioc['indicator'][:16]}",
                "type": f"IOC ({ioc.get('type')})",
                "color": color,
                "size": 18,
                "hover": f"Indicator: {ioc['indicator']}<br>Type: {ioc.get('type')}<br>Risk: {ioc.get('risk_level')}"
            })
            edges.append((0, current_idx))
            current_idx += 1

        # If no relations found, add an empty indicator
        if len(nodes) == 1:
            nodes.append({
                "id": 1,
                "label": "No Prior Ingested Records",
                "type": "Standalone",
                "color": "#64748b",
                "size": 16,
                "hover": "Not observed in uploaded documents or logs."
            })
            edges.append((0, 1))

        # Position nodes in a circular star layout around the center (0,0)
        num_outer = len(nodes) - 1
        x_coords = [0.0]
        y_coords = [0.0]

        radius = 1.6
        for i in range(num_outer):
            angle = (2 * math.pi * i) / max(1, num_outer)
            x_coords.append(radius * math.cos(angle))
            y_coords.append(radius * math.sin(angle))

        # Build Edge Traces
        edge_x = []
        edge_y = []
        for src, dst in edges:
            edge_x.extend([x_coords[src], x_coords[dst], None])
            edge_y.extend([y_coords[src], y_coords[dst], None])

        edge_trace = go.Scatter(
            x=edge_x,
            y=edge_y,
            line=dict(width=1.5, color="rgba(148, 163, 184, 0.35)"),
            hoverinfo="none",
            mode="lines"
        )

        # Build Node Traces
        node_trace = go.Scatter(
            x=x_coords,
            y=y_coords,
            mode="markers+text",
            text=[n["label"] for n in nodes],
            textposition="top center",
            textfont=dict(size=10, color="#f8fafc", family="JetBrains Mono, monospace"),
            hoverinfo="text",
            hovertext=[n["hover"] for n in nodes],
            marker=dict(
                color=[n["color"] for n in nodes],
                size=[n["size"] for n in nodes],
                line=dict(width=2, color="#0f172a"),
                symbol="circle"
            )
        )

        # Create Plotly Layout
        fig = go.Figure(
            data=[edge_trace, node_trace],
            layout=go.Layout(
                showlegend=False,
                hovermode="closest",
                margin=dict(b=20, l=20, r=20, t=30),
                paper_bgcolor="rgba(15, 23, 42, 0.4)",
                plot_bgcolor="rgba(15, 23, 42, 0.0)",
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                height=380
            )
        )

        return fig
