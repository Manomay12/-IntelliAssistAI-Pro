"""
Automated IOC (Indicator of Compromise) Extraction & Intelligence Engine for IntelAssist AI.
Extracts and normalizes IPv4, IPv6, Domains, URLs, Email addresses, MD5/SHA1/SHA256 hashes,
CVE identifiers, suspicious filenames, and MITRE technique IDs from unstructured text,
threat reports, and log files with context extraction, risk level classification, and defanging.
"""

import re
import ipaddress
from typing import List, Dict, Any, Optional, Set, Tuple

# Pre-compiled Regex Patterns for Cyber Indicators
IPV4_REGEX = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\[\.\]|\(\.\)|\.)){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

IPV6_REGEX = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|\b:(?::[0-9a-fA-F]{1,4}){1,7}\b'
)

URL_REGEX = re.compile(
    r'\b(?:h[tx]{2}ps?|ftp)://(?:\[\.\]|[\w\-._~:/?#\[\]@!$&\'()*+,;=])+',
    re.IGNORECASE
)

EMAIL_REGEX = re.compile(
    r'\b[a-zA-Z0-9._%+-]+(?:\[@\]|@)[a-zA-Z0-9.-]+(?:\[\.\]|\.)[a-zA-Z]{2,}\b'
)

DOMAIN_REGEX = re.compile(
    r'\b(?!(?:https?|ftp|hxxps?)://)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\[\.\]|\.)){1,4}(?:com|net|org|io|xyz|ru|cn|top|cc|info|biz|co|me|online|site|live|tech|club|vip|pro|us|uk|de|eu|in|onion|gov|edu)\b',
    re.IGNORECASE
)

MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_REGEX = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')

CVE_REGEX = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
MITRE_TECH_REGEX = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".ps1", ".vbs", ".bat", ".sh", ".py", ".bin",
    ".elf", ".php", ".jsp", ".asp", ".aspx", ".jar", ".scr", ".hta"
}

SUSPICIOUS_FILENAMES = [
    r'\b[\w\-_.]*(?:mimikatz|meterpreter|beacon|cobalt|webshell|backdoor|exploit|payload|inject|keylogger|rootkit|dropper|pwdump|procdump)[\w\-_.]*\.(?:exe|dll|ps1|sh|bin|elf|vbs|bat|php|jsp|asp)\b',
    r'\b(?:shell|cmd|powershell|svchost_fake|lsass_dump|malware|evil|nc|ncat)\.(?:exe|sh|php|jsp|aspx|py|bin)\b'
]
SUSPICIOUS_FILE_COMPILED = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_FILENAMES]

# Risk Context Trigger Keywords
HIGH_RISK_KEYWORDS = [
    "c2", "command and control", "beacon", "ransomware", "backdoor", "exploit",
    "cobalt strike", "mimikatz", "privilege escalation", "data exfiltration",
    "unauthorized access", "remote code execution", "rce", "phishing campaign",
    "malicious payload", "zero-day", "threat actor", "apt29", "apt28", "lazarus"
]

MEDIUM_RISK_KEYWORDS = [
    "suspicious", "failed login", "brute force", "port scan", "reconnaissance",
    "unusual traffic", "denied", "blocked", "sql injection", "path traversal",
    "anomalous", "probe", "crawler", "spoofed", "phishing"
]

class IOCExtractor:
    """High-performance extraction and intelligence engine for Indicators of Compromise (IOCs)."""

    @staticmethod
    def refang(indicator: str) -> str:
        """Convert defanged indicator back to standard notation."""
        if not indicator:
            return ""
        s = indicator.replace("[.]", ".").replace("(.)", ".")
        s = s.replace("[@]", "@").replace("(@)", "@")
        s = re.sub(r'^hxxp', 'http', s, flags=re.IGNORECASE)
        s = re.sub(r'^hxxps', 'https', s, flags=re.IGNORECASE)
        return s.strip()

    @staticmethod
    def defang(indicator: str) -> str:
        """Defang an indicator to prevent accidental clicks or execution."""
        if not indicator:
            return ""
        s = indicator.replace(".", "[.]").replace("@", "[@]")
        s = re.sub(r'^http', 'hxxp', s, flags=re.IGNORECASE)
        s = re.sub(r'^https', 'hxxps', s, flags=re.IGNORECASE)
        return s.strip()

    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        """Check if an IPv4 address belongs to RFC 1918 private / loopback / link-local ranges."""
        try:
            clean_ip = IOCExtractor.refang(ip_str)
            ip_obj = ipaddress.ip_address(clean_ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False

    @classmethod
    def evaluate_risk_level(cls, indicator: str, ioc_type: str, context: str) -> Tuple[str, str, str]:
        """
        Evaluate heuristic risk level, context reason, and confidence.
        Returns: (risk_level, context_tag, confidence)
        """
        ctx_lower = context.lower()
        ind_clean = cls.refang(indicator).lower()

        # Check for High Risk triggers
        for kw in HIGH_RISK_KEYWORDS:
            if kw in ctx_lower:
                return "Critical" if "c2" in kw or "ransomware" in kw or "rce" in kw else "High", kw.title(), "High"

        # Check for Medium Risk triggers
        for kw in MEDIUM_RISK_KEYWORDS:
            if kw in ctx_lower:
                return "Elevated" if "brute force" in kw or "sql" in kw else "Medium", kw.title(), "High"

        # Type-specific defaults
        if ioc_type == "CVE":
            return "High", "Vulnerability Identifier", "High"
        elif ioc_type in ["SHA256", "MD5", "SHA1"]:
            return "Elevated", "Cryptographic Artifact", "Medium"
        elif ioc_type == "IP Address":
            if cls.is_private_ip(indicator):
                return "Low", "Internal Network Host", "High"
            return "Medium", "External Host", "Medium"
        elif ioc_type == "Suspicious File":
            return "High", "Executable Tool / Script", "High"
        elif ioc_type == "URL":
            return "Medium", "Network Endpoint", "Medium"

        return "Low", "Observed Indicator", "Medium"

    @classmethod
    def extract_from_text(
        cls,
        text: str,
        source_name: str = "Document",
        page_number: int = 1
    ) -> List[Dict[str, Any]]:
        """
        Extract all Indicators of Compromise from raw text with context and risk classifications.
        """
        if not text:
            return []

        results: List[Dict[str, Any]] = []
        seen_indicators: Set[Tuple[str, str]] = set()

        def add_ioc(raw_value: str, ioc_type: str, match_span: Tuple[int, int]):
            norm_val = cls.refang(raw_value).strip(" \t\n,;:\"'()[]{}<>")
            
            # Additional validation and normalization
            if ioc_type in ["Domain", "URL", "Email", "SHA256", "SHA1", "MD5"]:
                norm_val = norm_val.lower()

            if ioc_type == "IP Address":
                try:
                    ip_obj = ipaddress.ip_address(norm_val)
                    # Filter out version numbers like 1.38.0 or 2.2.2 if matched erroneously
                    # (must be valid IPv4)
                    if ip_obj.version != 4:
                        return
                except ValueError:
                    return
            elif ioc_type == "Domain":
                if len(norm_val) < 4 or "/" in norm_val or "@" in norm_val or norm_val.replace(".", "").isdigit():
                    return

            key = (norm_val.lower(), ioc_type)
            if key in seen_indicators:
                return
            seen_indicators.add(key)

            # Extract 80 chars surrounding context
            start_ctx = max(0, match_span[0] - 80)
            end_ctx = min(len(text), match_span[1] + 80)
            context_snippet = text[start_ctx:end_ctx].replace("\n", " ").strip()

            risk_level, context_tag, confidence = cls.evaluate_risk_level(norm_val, ioc_type, context_snippet)

            results.append({
                "indicator": norm_val,
                "defanged": cls.defang(norm_val),
                "type": ioc_type,
                "source": source_name,
                "page": page_number,
                "risk_level": risk_level,
                "context": context_tag,
                "context_snippet": context_snippet,
                "confidence": confidence
            })

        # 1. IPv4 Addresses
        for match in IPV4_REGEX.finditer(text):
            add_ioc(match.group(0), "IP Address", match.span())

        # 2. IPv6 Addresses
        for match in IPV6_REGEX.finditer(text):
            val = match.group(0)
            if ":" in val and len(val) >= 4:
                add_ioc(val, "IPv6 Address", match.span())

        # 3. URLs
        for match in URL_REGEX.finditer(text):
            add_ioc(match.group(0), "URL", match.span())

        # 4. Emails
        for match in EMAIL_REGEX.finditer(text):
            add_ioc(match.group(0), "Email", match.span())

        # 5. Domains (checked after URLs to avoid duplicates)
        for match in DOMAIN_REGEX.finditer(text):
            add_ioc(match.group(0), "Domain", match.span())

        # 6. Hashes: SHA256, SHA1, MD5
        for match in SHA256_REGEX.finditer(text):
            add_ioc(match.group(0).lower(), "SHA256", match.span())

        for match in SHA1_REGEX.finditer(text):
            val = match.group(0).lower()
            if not any(val in res["indicator"].lower() for res in results if res["type"] == "SHA256"):
                add_ioc(val, "SHA1", match.span())

        for match in MD5_REGEX.finditer(text):
            val = match.group(0).lower()
            if not any(val in res["indicator"].lower() for res in results if res["type"] in ["SHA256", "SHA1"]):
                add_ioc(val, "MD5", match.span())

        # 7. CVE Identifiers
        for match in CVE_REGEX.finditer(text):
            add_ioc(match.group(0).upper(), "CVE", match.span())

        # 8. MITRE Techniques
        for match in MITRE_TECH_REGEX.finditer(text):
            add_ioc(match.group(0).upper(), "MITRE Technique", match.span())

        # 9. Suspicious Filenames
        for pat in SUSPICIOUS_FILE_COMPILED:
            for match in pat.finditer(text):
                add_ioc(match.group(0), "Suspicious File", match.span())

        return results

    @classmethod
    def aggregate_document_iocs(cls, document_registry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract and aggregate unique IOCs across all documents in the registry.
        """
        all_iocs: List[Dict[str, Any]] = []
        ioc_map: Dict[str, Dict[str, Any]] = {}

        for filename, doc_info in document_registry.items():
            full_text = doc_info.get("full_text", "")
            if not full_text:
                continue

            doc_iocs = cls.extract_from_text(full_text, source_name=filename)
            for ioc in doc_iocs:
                ind = ioc["indicator"]
                itype = ioc["type"]
                key = f"{ind}|{itype}"

                if key not in ioc_map:
                    ioc_map[key] = {
                        "indicator": ind,
                        "defanged": ioc["defanged"],
                        "type": itype,
                        "sources": [filename],
                        "risk_level": ioc["risk_level"],
                        "context": ioc["context"],
                        "context_snippets": [ioc["context_snippet"]],
                        "confidence": ioc["confidence"],
                        "occurrences": 1
                    }
                else:
                    if filename not in ioc_map[key]["sources"]:
                        ioc_map[key]["sources"].append(filename)
                    ioc_map[key]["occurrences"] += 1
                    # Elevate risk if found in multiple files
                    if len(ioc_map[key]["sources"]) > 1 and ioc_map[key]["risk_level"] in ["Low", "Medium"]:
                        ioc_map[key]["risk_level"] = "Elevated"

        return list(ioc_map.values())
