import os
import csv
from typing import List, Dict
from core.vulnerability_checker import Vulnerability
from core.sbom_generator import SBOMComponent

class ReportWriter:
    @staticmethod
    def write_csv_report(vulnerabilities: List[Vulnerability], sbom_components: List[SBOMComponent], output_path: str):
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Component', 'Version', 'CVE', 'Severity', 'CVSS Score', 'Remediation', 'License', 'Supplier', 'File Path'])
            for vuln in vulnerabilities:
                comp = next((c for c in sbom_components if c.name == vuln.package_name and c.version == vuln.version), None)
                writer.writerow([
                    vuln.package_name,
                    vuln.version,
                    vuln.cve_id,
                    vuln.severity,
                    vuln.cvss_score,
                    vuln.remediation or '',
                    comp.license if comp else '',
                    comp.supplier if comp else '',
                    comp.file_path if comp else ''
                ])

    @staticmethod
    def write_html_report(vulnerabilities: List[Vulnerability], sbom_components: List[SBOMComponent], output_path: str, compliance_flags: Dict[str, bool] = None):
        html = ['<html><head><title>Java SCA & SBOM Report</title>\n'
                '<style>\n'
                'body { font-family: Arial, sans-serif; margin: 30px; background: #f9f9f9; }\n'
                'h1, h2, h3 { text-align: center; margin-top: 30px; margin-bottom: 20px; }\n'
                'table { border-collapse: collapse; width: 100%; margin: 20px 0; background: #fff; }\n'
                'th, td { border: 1px solid #ccc; padding: 8px 12px; text-align: left; }\n'
                'th { background: #e0e0e0; }\n'
                'tr:nth-child(even) { background: #f2f2f2; }\n'
                'ul { margin-left: 40px; }\n'
                '</style></head><body>']
        html.append('<h1>Vulnerabilities</h1>')
        html.append('<table border="1"><tr><th>Component</th><th>Version</th><th>CVE</th><th>Severity</th><th>CVSS</th><th>Remediation</th></tr>')
        for vuln in vulnerabilities:
            html.append(f'<tr><td>{vuln.package_name}</td><td>{vuln.version}</td><td>{vuln.cve_id}</td><td>{vuln.severity}</td><td>{vuln.cvss_score}</td><td>{vuln.remediation or ""}</td></tr>')
        html.append('</table>')
        html.append('<h2>License Summary</h2>')
        license_counts = {}
        for comp in sbom_components:
            license_counts[comp.license] = license_counts.get(comp.license, 0) + 1
        html.append('<ul>')
        for lic, count in license_counts.items():
            html.append(f'<li>{lic}: {count}</li>')
        html.append('</ul>')
        html.append('<h2>SBOM Metadata Summary</h2>')
        html.append(f'<p>Total Components: {len(sbom_components)}</p>')
        html.append('<ul>')
        for comp in sbom_components:
            html.append(f'<li>{comp.name} {comp.version} ({comp.license}) - {comp.file_path}</li>')
        html.append('</ul>')
        if compliance_flags:
            html.append('<h2>Compliance Flags</h2><ul>')
            for flag, status in compliance_flags.items():
                html.append(f'<li>{flag}: {"PASS" if status else "FAIL"}</li>')
            html.append('</ul>')
        html.append('</body></html>')
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(html))

    @staticmethod
    def write_unified_html_report(
        output_path: str,
        cyclonedx_json_path: str = None,
        spdx_json_path: str = None,
        depcheck_html_path: str = None,
        compliance_summaries: dict = None,
        sbom_components: list = None,
        project_name: str = None,
        scanned_files: list = None
    ):
        import datetime
        report_title = f"{project_name} SCA & SBOM Report" if project_name else "Unified SCA & SBOM Report"
        html = [f'<html><head><title>{report_title}</title>\n'
                '<style>\n'
                'body { font-family: Arial, sans-serif; margin: 30px; background: #f9f9f9; }\n'
                'h1, h2, h3 { text-align: center; margin-top: 30px; margin-bottom: 20px; }\n'
                'table { border-collapse: collapse; width: 100%; margin: 20px 0; background: #fff; }\n'
                'th, td { border: 1px solid #ccc; padding: 8px 12px; text-align: left; }\n'
                'th { background: #e0e0e0; }\n'
                'tr:nth-child(even) { background: #f2f2f2; }\n'
                'ul { margin-left: 40px; }\n'
                '</style></head><body>']
        html.append(f'<h1>{report_title}</h1>')
        # SBOM Metadata
        html.append('<h2>SBOM Metadata</h2>')
        html.append(f'<p>SBOM Generation Timestamp: {datetime.datetime.utcnow().isoformat()}Z</p>')
        html.append(f'<p>Generated By: java_sbom_sca_tool</p>')
        # Scanned Files Section
        if scanned_files:
            html.append('<h2>Scanned Files</h2>')
            html.append('<table border="1"><tr><th>File Path</th><th>Type</th><th>SHA-256</th></tr>')
            for f in scanned_files:
                html.append(f'<tr><td>{f.get("path","")}</td><td>{f.get("type","Unknown")}</td><td>{f.get("hash","N/A")}</td></tr>')
            html.append('</table>')
        # Component Inventory Table
        if sbom_components:
            html.append('<h2>Component Inventory</h2>')
            html.append('<table border="1"><tr>'
                '<th>Component Name</th><th>Version</th><th>Description</th><th>Supplier/Vendor</th><th>License Type</th>'
                '<th>Cryptographic Hash (SHA-256)</th><th>Direct Dependencies</th><th>Transitive Dependencies</th>'
                '<th>CVE ID</th><th>CVSS Severity Score</th><th>Exploitability Status</th><th>Remediation Guidance</th>'
                '<th>Affected Version Range</th><th>Component Release Date</th><th>SBOM Generation Timestamp</th>'
                '<th>SBOM Author/Tool</th><th>Criticality Rating</th><th>Is Executable (Yes/No)</th><th>Is Archive (Yes/No)</th>'
                '<th>Has Known Unknowns (Yes/No)</th><th>CI/CD Integration (Yes/No)</th><th>Patch Available (Yes/No)</th>'
                '<th>Patch Applied Date</th><th>Vulnerability Monitoring Status</th><th>Policy Reference</th>'
                '<th>Vendor Risk Assessment Status</th><th>Quarterly Risk Review Date</th><th>SBOM Audit Trail Reference</th>'
                '</tr>')
            for comp in sbom_components:
                html.append(f'<tr>'
                    f'<td>{comp.name}</td>'
                    f'<td>{comp.version}</td>'
                    f'<td>{comp.description or "Unknown"}</td>'
                    f'<td>{comp.supplier or "Unknown"}</td>'
                    f'<td>{comp.license or "Unknown"}</td>'
                    f'<td>{comp.hash_sha256 or "Unknown"}</td>'
                    f'<td>{", ".join(getattr(comp, "direct_dependencies", [])) if hasattr(comp, "direct_dependencies") else "Unknown"}</td>'
                    f'<td>{", ".join(getattr(comp, "transitive_dependencies", [])) if hasattr(comp, "transitive_dependencies") else "Unknown"}</td>'
                    f'<td>{", ".join(comp.cve_ids) if comp.cve_ids else "N/A"}</td>'
                    f'<td>{comp.severity or "N/A"}</td>'
                    f'<td>{comp.exploitability or "N/A"}</td>'
                    f'<td>{comp.remediation or "N/A"}</td>'
                    f'<td>{getattr(comp, "affected_version_range", "Unknown")}</td>'
                    f'<td>{comp.release_date or "Unknown"}</td>'
                    f'<td>{comp.sbom_timestamp or "Unknown"}</td>'
                    f'<td>{comp.generated_by or "Unknown"}</td>'
                    f'<td>{comp.criticality or "Unknown"}</td>'
                    f'<td>{"Yes" if comp.executable_flag else "No"}</td>'
                    f'<td>{"Yes" if getattr(comp, "is_archive", False) else "No"}</td>'
                    f'<td>{"Yes" if comp.known_unknown else "No"}</td>'
                    f'<td>{"Yes" if getattr(comp, "ci_cd_integration", False) else "No"}</td>'
                    f'<td>{"Yes" if getattr(comp, "patch_available", False) else "No"}</td>'
                    f'<td>{getattr(comp, "patch_applied_date", "N/A")}</td>'
                    f'<td>{getattr(comp, "vuln_monitoring_status", "N/A")}</td>'
                    f'<td>{getattr(comp, "policy_reference", "N/A")}</td>'
                    f'<td>{getattr(comp, "vendor_risk_assessment_status", "N/A")}</td>'
                    f'<td>{getattr(comp, "quarterly_risk_review_date", "N/A")}</td>'
                    f'<td>{getattr(comp, "sbom_audit_trail_reference", "N/A")}</td>'
                    '</tr>')
            html.append('</table>')
        # CycloneDX SBOM summary
        if cyclonedx_json_path and os.path.exists(cyclonedx_json_path):
            import json
            with open(cyclonedx_json_path, encoding='utf-8') as f:
                try:
                    cdx = json.load(f)
                    html.append('<h2>CycloneDX SBOM Summary</h2>')
                    html.append(f'<p>Spec Version: {cdx.get("specVersion", "N/A")}, Components: {len(cdx.get("components", []))}</p>')
                    html.append('<ul>')
                    for comp in cdx.get("components", [])[:20]:
                        html.append(f'<li>{comp.get("name")} {comp.get("version")} ({comp.get("type")})</li>')
                    if len(cdx.get("components", [])) > 20:
                        html.append('<li>...and more</li>')
                    html.append('</ul>')
                except Exception:
                    html.append('<p>Could not parse CycloneDX SBOM.</p>')
        # SPDX SBOM summary
        if spdx_json_path and os.path.exists(spdx_json_path):
            import json
            with open(spdx_json_path, encoding='utf-8') as f:
                try:
                    spdx = json.load(f)
                    html.append('<h2>SPDX SBOM Summary</h2>')
                    html.append(f'<p>SPDX Version: {spdx.get("spdxVersion", "N/A")}, Packages: {len(spdx.get("packages", []))}</p>')
                    html.append('<ul>')
                    for pkg in spdx.get("packages", [])[:20]:
                        html.append(f'<li>{pkg.get("name")} {pkg.get("versionInfo")}</li>')
                    if len(spdx.get("packages", [])) > 20:
                        html.append('<li>...and more</li>')
                    html.append('</ul>')
                except Exception:
                    html.append('<p>Could not parse SPDX SBOM.</p>')
        # Dependency-Check HTML
        if depcheck_html_path and os.path.exists(depcheck_html_path):
            html.append('<h2>OWASP Dependency-Check Vulnerability Report</h2>')
            try:
                with open(depcheck_html_path, encoding='utf-8') as f:
                    depcheck_html = f.read()
                # Extract body content only
                import re
                body = re.search(r'<body[^>]*>([\s\S]*?)</body>', depcheck_html, re.IGNORECASE)
                if body:
                    html.append(body.group(1))
                else:
                    html.append('<p>Could not extract Dependency-Check report body.</p>')
            except Exception:
                html.append('<p>Could not read Dependency-Check report.</p>')
        # Compliance summaries
        if compliance_summaries:
            html.append('<h2>Compliance Summaries</h2>')
            for mode, summary_path in compliance_summaries.items():
                if os.path.exists(summary_path):
                    html.append(f'<h3>{mode.upper()} Compliance</h3>')
                    with open(summary_path, encoding='utf-8') as f:
                        html.append(f.read())
        html.append('</body></html>')
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(html))
