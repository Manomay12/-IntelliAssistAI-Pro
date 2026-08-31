"""
Conversation management and history tracking service for IntelliAssist AI.
Manages multi-session conversation logs, message storage, metadata, and persistence.
"""

import json
import time
import uuid
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from utils.config import CONVERSATIONS_DIR

logger = logging.getLogger(__name__)

class ConversationManager:
    """Manages chat sessions, messages, citations, feedback, and history persistence."""

    def __init__(self, storage_dir: Path = CONVERSATIONS_DIR):
        self.storage_dir = storage_dir
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.current_session_id = str(uuid.uuid4())[:8]
        self.messages: List[Dict[str, Any]] = []
        self.title: str = "New Conversation"
        self.associated_docs: List[str] = []
        self.created_at: str = time.strftime("%Y-%m-%d %H:%M:%S")

    def new_session(self, title: str = "New Conversation", associated_docs: Optional[List[str]] = None) -> str:
        """Start a fresh conversation session."""
        self.current_session_id = str(uuid.uuid4())[:8]
        self.messages = []
        self.title = title
        self.associated_docs = associated_docs or []
        self.created_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return self.current_session_id

    def add_message(
        self,
        role: str,
        content: str,
        sources: Optional[List[Dict[str, Any]]] = None,
        model_info: Optional[Dict[str, Any]] = None
    ):
        """Append a user or assistant message with metadata."""
        msg_id = str(uuid.uuid4())[:8]
        timestamp = time.strftime("%H:%M:%S")
        
        msg = {
            "id": msg_id,
            "role": role,
            "content": content,
            "timestamp": timestamp,
            "sources": sources or [],
            "model_info": model_info or {},
            "feedback": None  # 'up', 'down', or None
        }
        self.messages.append(msg)
        
        # Auto-update conversation title if it was the default "New Conversation"
        if role == "user" and self.title == "New Conversation":
            words = content.strip().split()
            self.title = " ".join(words[:6]).title()
            if len(words) > 6:
                self.title += "..."

        self.save_session()

    def set_feedback(self, msg_id: str, feedback: str):
        """Set user feedback ('up' or 'down') on an assistant message."""
        for m in self.messages:
            if m.get("id") == msg_id:
                m["feedback"] = feedback
                break
        self.save_session()

    def save_session(self):
        """Save the current session to JSON."""
        if not self.messages:
            return

        session_data = {
            "session_id": self.current_session_id,
            "title": self.title,
            "created_at": self.created_at,
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "associated_docs": self.associated_docs,
            "message_count": len(self.messages),
            "messages": self.messages
        }
        file_path = self.storage_dir / f"session_{self.current_session_id}.json"
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(session_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.warning("Failed to save session %s: %s", self.current_session_id, e)

    def load_session(self, session_id: str) -> bool:
        """Load a previous session by ID."""
        file_path = self.storage_dir / f"session_{session_id}.json"
        if not file_path.exists():
            return False

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.current_session_id = data.get("session_id", session_id)
            self.title = data.get("title", "Conversation")
            self.created_at = data.get("created_at", "")
            self.associated_docs = data.get("associated_docs", [])
            self.messages = data.get("messages", [])
            return True
        except Exception as e:
            logger.error("Error loading session %s: %s", session_id, e)
            return False

    def list_all_sessions(self) -> List[Dict[str, Any]]:
        """List all saved conversations sorted by recent update time."""
        sessions = []
        for p in self.storage_dir.glob("session_*.json"):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                sessions.append({
                    "session_id": data.get("session_id"),
                    "title": data.get("title", "Untitled"),
                    "created_at": data.get("created_at", ""),
                    "updated_at": data.get("updated_at", ""),
                    "message_count": data.get("message_count", len(data.get("messages", []))),
                    "associated_docs": data.get("associated_docs", []),
                    "file_path": str(p)
                })
            except Exception:
                continue

        sessions.sort(key=lambda x: x.get("updated_at", x.get("created_at", "")), reverse=True)
        return sessions

    def clear_current_chat(self):
        """Clear all messages from the current conversation."""
        self.messages = []
        file_path = self.storage_dir / f"session_{self.current_session_id}.json"
        if file_path.exists():
            try:
                file_path.unlink()
            except Exception:
                pass
        self.title = "New Conversation"

    def delete_session(self, session_id: str) -> bool:
        """Delete a saved session file."""
        file_path = self.storage_dir / f"session_{session_id}.json"
        if file_path.exists():
            try:
                file_path.unlink()
            except Exception:
                pass
            if self.current_session_id == session_id:
                self.new_session()
            return True
        return False

    def delete_all_sessions(self) -> int:
        """Delete all saved sessions and reset current active session."""
        count = 0
        for p in self.storage_dir.glob("session_*.json"):
            try:
                p.unlink()
                count += 1
            except Exception:
                pass
        self.new_session()
        return count

    def rename_session(self, session_id: str, new_title: str) -> bool:
        """Rename an existing session."""
        file_path = self.storage_dir / f"session_{session_id}.json"
        if not file_path.exists():
            return False
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            data["title"] = new_title
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            if self.current_session_id == session_id:
                self.title = new_title
            return True
        except Exception:
            return False

    def export_as_markdown(self) -> str:
        """Export current chat transcript to formatted Markdown."""
        lines = [
            f"# {self.title}",
            f"**Session ID:** `{self.current_session_id}` | **Date:** {self.created_at}",
            f"**Documents Analyzed:** {', '.join(self.associated_docs) if self.associated_docs else 'None'}",
            "\n---\n"
        ]

        for msg in self.messages:
            role = "👤 **User**" if msg["role"] == "user" else "🤖 **IntelliAssist AI**"
            lines.append(f"### {role} ({msg.get('timestamp', '')})")
            lines.append(f"{msg['content']}\n")
            
            if msg.get("sources"):
                lines.append("**Sources Consulted:**")
                for s in msg["sources"]:
                    lines.append(f"- 📄 `{s['filename']}` (Page {s['page_number']}) — Relevance: {s.get('similarity_percentage', 0)}%")
                lines.append("")
            lines.append("---\n")

        return "\n".join(lines)
