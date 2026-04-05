# Domain-Analyzer-OSINT-Cybersecurity-Toolkit

A multi-layer domain intelligence tool with a cyberpunk dark GUI, built in Python with Tkinter. Designed for security researchers, sysadmins, and OSINT practitioners who want fast, consolidated domain reconnaissance from a single interface.

Features
Always available (no API keys needed)

WHOIS Lookup — registrar, org, name servers, creation/expiry dates with expiry warnings
DNS Records — A, AAAA, MX, NS, TXT, SOA, CNAME resolution via dnspython
SSL/TLS Certificate — subject, issuer, SANs, validity window, days remaining
Port Scanner — threaded scan of 17 common ports (FTP, SSH, HTTP, RDP, MySQL, etc.)
HTTP Header Audit — security header checks (HSTS, CSP, X-Frame-Options, etc.) + full header dump
GeoIP — country, region, city, ISP, ASN via ip-api.com (free, no key)
URLhaus Feed — malware URL lookup via abuse.ch (free, no key)

API Key Setup

All keys are optional. The tool works without any keys, but enriched data requires:

VirusTotal — virustotal.com/gui/join-us — Free: 4 req/min, 500/day
Shodan — account.shodan.io/register — Free tier with limited host queries
AbuseIPDB — abuseipdb.com/register — Free: 1,000 checks/day

Installation
bashgit clone https://github.com/yourname/domain-analyzer.git
cd domain-analyzer
pip install requests dnspython python-whois pyOpenSSL
python domain_analyzer.py
Usage

Enter a domain in the target field (e.g. example.com) and press ANALYZE or hit Enter.
Results populate across tabbed panels: WHOIS · DNS · IP/GEO · SSL · PORTS · HTTP HDR · REPUTATION.
Optionally open the API KEYS tab, paste your keys, and click SAVE KEYS FOR SESSION to unlock enriched data from VirusTotal, Shodan, and AbuseIPDB.
Export results as JSON or TXT via the toolbar buttons.

Export
Results can be exported after any analysis:

JSON — full structured data for each module
TXT — human-readable report with all sections

Files are saved with the format: domain_analyzer_<domain>_<timestamp>.<ext>
