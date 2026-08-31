"""
Cybersecurity Sample Data Generator for IntelAssist AI.
Generates realistic, safe, high-fidelity sample threat advisories, SSH authentication logs,
firewall traffic logs, web server attack logs, and forensic incident reports for instant 1-click evaluation.
"""

import io
from pathlib import Path
import docx
from utils.config import SAMPLE_DATA_DIR

def create_sample_threat_report_docx(filepath: Path):
    """Create a structured sample DOCX Threat Intelligence Report."""
    doc = docx.Document()
    doc.add_heading("THREAT ADVISORY: APT29 (COZY BEAR) SPEAR-PHISHING CAMPAIGN", level=0)
    
    doc.add_heading("1. Executive Summary", level=1)
    doc.add_paragraph(
        "IntelAssist Threat Research has identified an active cyber espionage campaign attributed to threat actor "
        "APT29 (also tracked as Cozy Bear, Midnight Blizzard, NOBELIUM). The adversary utilizes targeted spear-phishing "
        "emails delivering malicious ZIP archives exploiting CVE-2023-38831 (WinRAR code execution vulnerability) to deploy "
        "custom Cobalt Strike beacons and backdoor payloads. The primary objectives appear to be credential harvesting, "
        "session hijacking, and long-term espionage across government, defense, and technology sectors."
    )
    
    doc.add_heading("2. Attack Flow & Technical Analysis", level=1)
    doc.add_paragraph(
        "Initial Access is established via phishing emails containing lure PDFs and weaponized archives. "
        "Upon extraction, the vulnerability triggers execution of a hidden batch script, which contacts external C2 server "
        "185.220.101.5 on port 443. The secondary stage downloads payload beacon.dll from domain cdn-update-service.org. "
        "Adversaries then perform local privilege escalation via sudo misconfigurations and OS credential dumping using Mimikatz."
    )
    
    doc.add_heading("3. Indicators of Compromise (IOC Table)", level=1)
    table = doc.add_table(rows=1, cols=4)
    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = "Indicator"
    hdr_cells[1].text = "Type"
    hdr_cells[2].text = "Risk Level"
    hdr_cells[3].text = "Context / Association"
    
    data = [
        ("185.220.101.5", "IPv4 Address", "Critical", "Primary APT29 Command & Control (C2)"),
        ("194.26.29.112", "IPv4 Address", "High", "Secondary Exfiltration Staging Node"),
        ("login-microsoft-secure.com", "Domain", "Critical", "Credential Harvesting Phishing Domain"),
        ("cdn-update-service.org", "Domain", "High", "Malware Payload Distribution Server"),
        ("https://login-microsoft-secure.com/auth/login", "URL", "Critical", "Phishing Landing Page"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA256", "Critical", "Weaponized Dropper Executable"),
        ("8f4e56c7a912e8b1a3d4f5e6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6", "SHA256", "High", "Cobalt Strike HTTPS Beacon DLL"),
        ("CVE-2023-38831", "CVE", "Critical", "WinRAR Processing Logic Remote Code Execution"),
        ("CVE-2021-44228", "CVE", "Critical", "Apache Log4j Remote Code Execution (Secondary Probe)"),
        ("mimikatz.exe", "Suspicious File", "Critical", "Credential Extraction Tool")
    ]
    for row_data in data:
        row_cells = table.add_row().cells
        for i, val in enumerate(row_data):
            row_cells[i].text = val
            
    doc.add_heading("4. MITRE ATT&CK Mapping & Mitigations", level=1)
    doc.add_paragraph(
        "- T1566.001 Spear-phishing Attachment: Block inbound emails containing password-protected ZIP/RAR files.\n"
        "- T1190 Exploit Public-Facing Application: Patch CVE-2023-38831 and ensure perimeter systems run updated software.\n"
        "- T1110 Brute Force: Enforce account lockouts after 5 invalid attempts and mandate Multi-Factor Authentication (MFA).\n"
        "- T1071.001 Web Protocols (C2): Block IP 185.220.101.5 and sinkhole domain cdn-update-service.org."
    )
    
    doc.save(filepath)

def create_sample_auth_log(filepath: Path):
    """Create a realistic Linux auth.log demonstrating SSH brute-force, successful login, and sudo escalation."""
    lines = []
    base_time = "Aug 31 10:20:"
    
    # 1. SSH Brute Force attempts from 185.220.101.5
    users = ["admin", "root", "oracle", "test", "support", "ubuntu", "guest", "deploy", "postgres", "jenkins"]
    sec = 10
    for u in users:
        for attempt in range(3):
            lines.append(f"Aug 31 10:20:{sec:02d} ubuntu-server sshd[14201]: Failed password for invalid user {u} from 185.220.101.5 port 49152 ssh2")
            sec = (sec + 1) % 60
            if sec == 0:
                base_time = "Aug 31 10:21:"
        
    for i in range(15):
        lines.append(f"Aug 31 10:22:{i:02d} ubuntu-server sshd[14350]: Failed password for ubuntu from 185.220.101.5 port 49200 ssh2")
        
    # 2. Compromise: Successful authentication after brute-force
    lines.append("Aug 31 10:24:12 ubuntu-server sshd[14400]: Accepted password for ubuntu from 185.220.101.5 port 49310 ssh2")
    lines.append("Aug 31 10:24:13 ubuntu-server systemd-logind[780]: New session 42 of user ubuntu.")
    lines.append("Aug 31 10:24:45 ubuntu-server sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/whoami")
    lines.append("Aug 31 10:25:02 ubuntu-server sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash")
    lines.append("Aug 31 10:25:30 ubuntu-server sudo:   ubuntu : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/cat /etc/shadow")
    lines.append("Aug 31 10:26:15 ubuntu-server sudo:   ubuntu : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/chmod 777 /etc/passwd")

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def create_sample_firewall_log(filepath: Path):
    """Create a firewall traffic log demonstrating port scans and outbound C2 beaconing."""
    lines = []
    # Inbound port scanning from 185.220.101.5
    ports = [21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080, 8443]
    for p in ports:
        lines.append(f"Aug 31 09:45:10 firewall kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:15:5d:01:ca:fe SRC=185.220.101.5 DST=192.168.1.100 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=1894 PROTO=TCP SPT=54210 DPT={p} WINDOW=64240 RES=0x00 SYN URGP=0")
        
    # Outbound C2 beaconing
    for i in range(5):
        lines.append(f"Aug 31 10:30:{i*10:02d} firewall kernel: [UFW ALLOW] IN=eth0 OUT=eth1 SRC=192.168.1.100 DST=185.220.101.5 LEN=140 PROTO=TCP SPT=49800 DPT=443 WINDOW=65535 ACK PSH URGP=0")
        
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def create_sample_web_log(filepath: Path):
    """Create an Nginx access log showing SQL injection, directory traversal, and webshell queries."""
    lines = [
        '185.220.101.5 - - [31/Aug/2026:10:15:01 +0000] "GET /index.html HTTP/1.1" 200 4520',
        '185.220.101.5 - - [31/Aug/2026:10:15:20 +0000] "GET /api/v1/users?id=1%27%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1" 500 240',
        '185.220.101.5 - - [31/Aug/2026:10:16:05 +0000] "GET /download.php?file=../../../../etc/passwd HTTP/1.1" 403 162',
        '185.220.101.5 - - [31/Aug/2026:10:17:33 +0000] "POST /uploads/shell.php?cmd=whoami HTTP/1.1" 200 85',
        '194.26.29.112 - - [31/Aug/2026:10:18:10 +0000] "GET /admin/config.php HTTP/1.1" 404 140',
        '192.168.1.50 - - [31/Aug/2026:10:19:00 +0000] "GET /dashboard HTTP/1.1" 200 8920'
    ]
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def create_sample_ioc_csv(filepath: Path):
    """Create a curated threat intelligence IOC CSV dataset."""
    content = """indicator,type,risk_level,context,threat_actor,cve_id,confidence
185.220.101.5,IP Address,Critical,Command and Control Server (C2),APT29,CVE-2023-38831,High
194.26.29.112,IP Address,High,Data Exfiltration Relay,APT29,,High
login-microsoft-secure.com,Domain,Critical,Credential Phishing Domain,APT29,,High
cdn-update-service.org,Domain,High,Malware Payload Delivery,APT29,,High
https://login-microsoft-secure.com/auth/login,URL,Critical,Phishing Endpoint,APT29,,High
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,SHA256,Critical,Weaponized Dropper Archive,APT29,CVE-2023-38831,High
8f4e56c7a912e8b1a3d4f5e6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6,SHA256,High,Cobalt Strike HTTPS Beacon DLL,APT29,,High
CVE-2023-38831,CVE,Critical,WinRAR Remote Code Execution Vulnerability,APT29,CVE-2023-38831,High
CVE-2021-44228,CVE,Critical,Apache Log4j RCE (Log4Shell),Generic Exploit,CVE-2021-44228,High
mimikatz.exe,Suspicious File,Critical,Credential Dumping Tool,APT29,,High
"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)

def create_sample_pdf(filepath: Path):
    """Generate a clean sample PDF document for APT29 Threat Advisory."""
    lines_p1 = [
        "INTELASSIST THREAT RESEARCH: APT29 COZY BEAR ADVISORY",
        "",
        "Executive Summary:",
        "IntelAssist Threat Research has detected a spear-phishing campaign attributed to threat actor APT29.",
        "The adversary distributes malicious archives exploiting CVE-2023-38831 for remote code execution.",
        "Observed C2 infrastructure includes IP 185.220.101.5 and domain login-microsoft-secure.com.",
        "",
        "Technical Analysis & Attack Chain:",
        "1. Spear-phishing email delivers weaponized ZIP file (SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855).",
        "2. WinRAR vulnerability CVE-2023-38831 executes hidden script without user interaction.",
        "3. Outbound beacon connects to 185.220.101.5 on port 443 to fetch beacon.dll.",
        "4. Adversary deploys mimikatz.exe for memory credential harvesting.",
        "",
        "Recommended Containment Actions:",
        "1. Immediately block IP 185.220.101.5 and 194.26.29.112 across all perimeter firewalls.",
        "2. Sinkhole phishing domain login-microsoft-secure.com and payload server cdn-update-service.org.",
        "3. Patch all endpoints against CVE-2023-38831 and enforce MFA on administrative accounts."
    ]

    def escape_pdf(txt):
        return txt.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    stream_p1 = "BT\n/F1 10 Tf\n14 TL\n50 750 Td\n"
    for line in lines_p1:
        if line == "":
            stream_p1 += "T*\n"
        elif "INTELASSIST THREAT RESEARCH" in line:
            stream_p1 += f"/F1 12 Tf\n({escape_pdf(line)}) Tj\n/F1 10 Tf\nT*\nT*\n"
        else:
            stream_p1 += f"({escape_pdf(line)}) Tj\nT*\n"
    stream_p1 += "ET"

    s1_bytes = stream_p1.encode('latin-1')

    pdf_out = io.BytesIO()
    pdf_out.write(b"%PDF-1.4\n")
    
    offsets = []
    def write_obj(num, content):
        offsets.append(pdf_out.tell())
        pdf_out.write(f"{num} 0 obj\n".encode('ascii'))
        pdf_out.write(content)
        pdf_out.write(b"\nendobj\n")

    write_obj(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    write_obj(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    write_obj(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>")
    write_obj(4, f"<< /Length {len(s1_bytes)} >>\nstream\n".encode('ascii') + s1_bytes + b"\nendstream")
    write_obj(5, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    xref_pos = pdf_out.tell()
    pdf_out.write(b"xref\n0 6\n0000000000 65535 f \n")
    for off in offsets:
        pdf_out.write(f"{off:010d} 00000 n \n".encode('ascii'))
    pdf_out.write(b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n")
    pdf_out.write(f"{xref_pos}\n%%EOF".encode('ascii'))

    with open(filepath, "wb") as f:
        f.write(pdf_out.getvalue())

def generate_all_samples() -> list[Path]:
    """Generate all academic and cyber sample datasets and return list of file paths."""
    SAMPLE_DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    p_threat_pdf = SAMPLE_DATA_DIR / "Sample_Threat_Intel_Report_APT29.pdf"
    p_auth_log = SAMPLE_DATA_DIR / "Sample_Auth_BruteForce.log"
    p_fw_log = SAMPLE_DATA_DIR / "Sample_Firewall_Traffic.log"
    p_web_log = SAMPLE_DATA_DIR / "Sample_Web_Server_Attacks.log"
    p_ioc_csv = SAMPLE_DATA_DIR / "Sample_IOC_Feed.csv"
    p_report_docx = SAMPLE_DATA_DIR / "Incident_Response_Forensics_Report.docx"

    create_sample_pdf(p_threat_pdf)
    create_sample_auth_log(p_auth_log)
    create_sample_firewall_log(p_fw_log)
    create_sample_web_log(p_web_log)
    create_sample_ioc_csv(p_ioc_csv)
    create_sample_threat_report_docx(p_report_docx)

    return [p_threat_pdf, p_auth_log, p_fw_log, p_web_log, p_ioc_csv, p_report_docx]
