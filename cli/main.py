import argparse
import os
import sys
from core.java_scanner import JavaScanner
from core.sbom_generator import SBOMGenerator
# from core.vulnerability_checker import VulnerabilityChecker
from core.report_writer import ReportWriter
from core.compliance_checker import ComplianceChecker
from core.depcheck_parser import parse_depcheck_html

def sanitize_path(path: str) -> str:
    # Ensure the path exists and is absolute
    abs_path = os.path.abspath(path)
    if not os.path.exists(abs_path):
        raise ValueError(f"Invalid path: {abs_path} does not exist.")
    return abs_path

def main():
    print(r"""

 ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄  ▄▄       ▄▄       ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄        ▄       ▄               ▄   ▄▄▄▄         ▄▄▄▄▄▄▄▄▄  
▐░░░░░░░░░░░▌▐░░░░░░░░░░▌ ▐░░░░░░░░░░░▌▐░░▌     ▐░░▌     ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░▌      ▐░▌     ▐░▌             ▐░▌▄█░░░░▌       ▐░░░░░░░░░▌ 
▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░▌░▌   ▐░▐░▌     ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░▌░▌     ▐░▌      ▐░▌           ▐░▌▐░░▌▐░░▌      ▐░█░█▀▀▀▀▀█░▌
▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌▐░▌▐░▌ ▐░▌▐░▌     ▐░▌          ▐░▌          ▐░▌▐░▌    ▐░▌       ▐░▌         ▐░▌  ▀▀ ▐░░▌      ▐░▌▐░▌    ▐░▌
▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌▐░▌       ▐░▌▐░▌ ▐░▐░▌ ▐░▌     ▐░▌ ▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄ ▐░▌ ▐░▌   ▐░▌        ▐░▌       ▐░▌      ▐░░▌      ▐░▌ ▐░▌   ▐░▌
▐░░░░░░░░░░░▌▐░░░░░░░░░░▌ ▐░▌       ▐░▌▐░▌  ▐░▌  ▐░▌     ▐░▌▐░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌  ▐░▌  ▐░▌         ▐░▌     ▐░▌       ▐░░▌      ▐░▌  ▐░▌  ▐░▌
 ▀▀▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░▌       ▐░▌▐░▌   ▀   ▐░▌     ▐░▌ ▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░▌   ▐░▌ ▐░▌          ▐░▌   ▐░▌        ▐░░▌      ▐░▌   ▐░▌ ▐░▌
          ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌▐░▌       ▐░▌     ▐░▌       ▐░▌▐░▌          ▐░▌    ▐░▌▐░▌           ▐░▌ ▐░▌         ▐░░▌      ▐░▌    ▐░▌▐░▌
 ▄▄▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌▐░▌       ▐░▌     ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░▌     ▐░▐░▌            ▐░▐░▌      ▄▄▄▄█░░█▄▄▄  ▄▐░█▄▄▄▄▄█░█░▌
▐░░░░░░░░░░░▌▐░░░░░░░░░░▌ ▐░░░░░░░░░░░▌▐░▌       ▐░▌     ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌      ▐░░▌             ▐░▌      ▐░░░░░░░░░░░▌▐░▌▐░░░░░░░░░▌ 
 ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀   ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀       ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀        ▀▀               ▀        ▀▀▀▀▀▀▀▀▀▀▀  ▀  ▀▀▀▀▀▀▀▀▀  
                                                                                                                                                                                                                               
SBOM Generator - PCI RBI Compliance
Developed by Ramjee Pentakota | All Rights Reserved
© 2025 Ramjee Pentakota

SUPPORTED OUTPUT FORMATS:
  html   Generate an HTML vulnerability/license report (sca_report.html)
  csv    Generate a CSV vulnerability/license report (sca_report.csv)
  json   Generate SBOMs in CycloneDX (sbom.cyclonedx.json) and SPDX (sbom.spdx.json) formats

QUICK USAGE:
  Show help:    python -m cli.main -h
  Example run:  python -m cli.main -p /path/to/java/project -o ./reports -f html,csv,json

DISCLAIMER: This tool is provided "AS IS" without warranty of any kind. Use at your own risk. The author is not liable for any damages or losses arising from the use of this software.
""")
    parser = argparse.ArgumentParser(
        prog="java_sbom_sca_tool",
        description=(
            """
Java SCA & SBOM Tool (PCI/RBI Compliant)

Easily scan your Java project for dependencies, generate SBOMs (CycloneDX/SPDX), check for vulnerabilities, and produce compliance and license reports.

SUPPORTED OUTPUT FORMATS:
  html   Generate an HTML vulnerability/license report (sca_report.html)
  csv    Generate a CSV vulnerability/license report (sca_report.csv)
  json   Generate SBOMs in CycloneDX (sbom.cyclonedx.json) and SPDX (sbom.spdx.json) formats

To specify multiple formats, use a comma-separated list (e.g., -f html,csv,json).

OUTPUT FILES:
  sbom.cyclonedx.json         CycloneDX SBOM (JSON)
  sbom.spdx.json              SPDX SBOM (JSON)
  sca_report.csv              Vulnerability and license report (CSV)
  sca_report.html             Vulnerability and license report (HTML)
  compliance_audit_summary_pci.html  PCI Compliance audit summary
  compliance_audit_summary_rbi.html  RBI Compliance audit summary

OPTIONS:
  -p, --path        Path to the root of the Java project to scan (required)
  -o, --output      Output directory to store all generated reports (default: current directory)
  -f, --format      Output formats: html, csv, json (comma-separated, default: html,csv,json)
  -h, --help        Show this help message and exit

EXAMPLE COMMANDS:
  python -m cli.main -p /path/to/java/project
  python -m cli.main -p . -o ./reports -f html,csv
  python -m cli.main -p . -o ./out -f json
  python -m cli.main -p /my/java/project -o . -f html
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '-p', '--path', required=True,
        help='Path to the root of the Java project to scan (required).'
    )
    parser.add_argument(
        '-o', '--output', default='.',
        help='Output directory to store all generated reports (default: current directory).'
    )
    parser.add_argument(
        '-f', '--format', default='html,csv,json',
        help='Output formats (comma-separated): html, csv, json. Default: html,csv,json.'
    )
    args = parser.parse_args()

    project_path = sanitize_path(args.path)
    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)
    output_types = [o.strip() for o in args.format.split(',')]

    # Ensure dependency-check.bat is found on Windows
    import platform
    if platform.system().lower() == "windows":
        depcheck_default = r"C:\\dependency-check\\bin\\dependency-check.bat"
        if os.path.exists(depcheck_default):
            depcheck_exe = depcheck_default
        else:
            # Try to find in PATH
            depcheck_exe = "dependency-check.bat"
        # Add default to PATH if not already
        if depcheck_default not in os.environ["PATH"]:
            os.environ["PATH"] += os.pathsep + r"C:\\dependency-check\\bin"
    else:
        depcheck_exe = "dependency-check"

    # Step 1: Scan Java project
    scanner = JavaScanner(project_path)
    scanner.scan()

    # Step 2: Generate SBOM using Dependency-Check XML + CycloneDX CLI and SPDX CLI tools (always run, fail if missing)
    import subprocess
    cyclonedx_json_path = os.path.join(output_dir, "sbom.cyclonedx.json")
    depcheck_xml_path = os.path.join(output_dir, "dependency-check-report.xml")
    spdx_json_path = os.path.join(output_dir, "sbom.spdx.json")

    # 1. Run Dependency-Check with XML output
    try:
        depcheck_cmd = [
            depcheck_exe, "--project", "SCA-Scan", "--scan", project_path, "--format", "XML", "--out", output_dir
        ]
        subprocess.run(depcheck_cmd, check=True)
    except Exception as e:
        print("[ERROR] Dependency-Check XML generation failed. Please ensure dependency-check is installed.")
        raise e

    # 2. Convert Dependency-Check XML to CycloneDX JSON using CycloneDX CLI
    try:
        cyclonedx_cmd = [
            "cyclonedx", "convert", "--input", depcheck_xml_path, "--output", cyclonedx_json_path
        ]
        subprocess.run(cyclonedx_cmd, check=True)
    except Exception as e:
        print("[ERROR] CycloneDX conversion failed. Please ensure cyclonedx-cli is installed.")
        raise e

    # 3. Run SPDX SBOM generator
    try:
        spdx_cmd = [
            "spdx-sbom-generator", "-p", project_path, "-o", output_dir
        ]
        subprocess.run(spdx_cmd, check=True)
    except Exception as e:
        print("[ERROR] SPDX SBOM generation failed. Please ensure spdx-sbom-generator is installed.")
        raise e

    # Parse CycloneDX and SPDX outputs
    import json
    with open(cyclonedx_json_path, encoding='utf-8') as f:
        cyclonedx_data = json.load(f)
    with open(spdx_json_path, encoding='utf-8') as f:
        spdx_data = json.load(f)

    # Fallback to Python implementation for file scanning (for extra file info)
    sbom_gen = SBOMGenerator()
    sbom_components = scanner.to_sbom_components(sbom_gen)
    for comp in sbom_components:
        sbom_gen.add_component(comp)

    # Step 3: Run OWASP Dependency-Check for SCA
    try:
        depcheck_cmd = [
            depcheck_exe, "--project", "SCA-Scan", "--scan", project_path, "--format", "HTML", "--out", os.path.join(output_dir, "dependency-check-report.html")
        ]
        subprocess.run(depcheck_cmd, check=True)
    except Exception:
        pass

    # Step 4: Only use OWASP Dependency-Check for SCA
    depcheck_html_path = os.path.join(output_dir, "dependency-check-report.html")
    vulnerabilities = []
    if os.path.exists(depcheck_html_path):
        vulnerabilities = parse_depcheck_html(depcheck_html_path)

    # Step 5: Compliance checks (PCI and RBI)
    for compliance_mode in ["pci", "rbi"]:
        compliance_checker = ComplianceChecker(compliance_mode)
        compliance_flags = compliance_checker.check(sbom_components, vulnerabilities)
        compliance_checker.generate_audit_summary(os.path.join(output_dir, f'compliance_audit_summary_{compliance_mode}.html'))

    # Step 6: Output unified HTML report
    compliance_summaries = {
        "pci": os.path.join(output_dir, 'compliance_audit_summary_pci.html'),
        "rbi": os.path.join(output_dir, 'compliance_audit_summary_rbi.html')
    }
    project_name = os.path.basename(os.path.normpath(project_path))
    report_filename = f"{project_name}_sca_sbom_report.html"
    ReportWriter.write_unified_html_report(
        output_path=os.path.join(output_dir, report_filename),
        cyclonedx_json_path=os.path.join(output_dir, 'sbom.cyclonedx.json'),
        spdx_json_path=os.path.join(output_dir, 'sbom.spdx.json'),
        depcheck_html_path=os.path.join(output_dir, 'dependency-check-report.html'),
        compliance_summaries=compliance_summaries,
        sbom_components=sbom_components,
        project_name=project_name
    )
    print("SCA & SBOM unified report generated in:", os.path.join(output_dir, report_filename))

    # Move intermediate files to a subdirectory for cleanliness
    intermediate_dir = os.path.join(output_dir, "intermediate")
    os.makedirs(intermediate_dir, exist_ok=True)
    for fname in [
        'sbom.cyclonedx.json',
        'sbom.spdx.json',
        'dependency-check-report.html',
        'compliance_audit_summary_pci.html',
        'compliance_audit_summary_rbi.html',
        'sca_report.csv',
        'sca_report.html'
    ]:
        fpath = os.path.join(output_dir, fname)
        if os.path.exists(fpath):
            os.replace(fpath, os.path.join(intermediate_dir, fname))

if __name__ == '__main__':
    main()
