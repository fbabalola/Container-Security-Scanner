#!/usr/bin/env python3
"""
Container Security Scanner
Automated container image vulnerability scanning using Trivy

Author: Firebami Babalola
"""

import subprocess
import json
import argparse
import sys
from datetime import datetime
from typing import List, Dict, Optional


class ContainerSecurityScanner:
    """Automated container security scanning using Trivy."""
    
    SEVERITY_LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
    
    def __init__(self, severity_filter: Optional[List[str]] = None):
        """
        Initialize the scanner.
        
        Args:
            severity_filter: List of severity levels to include (e.g., ['CRITICAL', 'HIGH'])
        """
        self.severity_filter = severity_filter or self.SEVERITY_LEVELS
        self._verify_trivy_installed()
    
    def _verify_trivy_installed(self) -> None:
        """Verify Trivy is installed and accessible."""
        try:
            result = subprocess.run(
                ['trivy', '--version'],
                capture_output=True,
                text=True,
                check=True
            )
            print(f"[+] Trivy detected: {result.stdout.strip()}")
        except FileNotFoundError:
            print("[!] ERROR: Trivy is not installed or not in PATH")
            print("    Install with: brew install aquasecurity/trivy/trivy")
            sys.exit(1)
    
    def scan_image(self, image: str) -> Dict:
        """
        Scan a container image for vulnerabilities.
        
        Args:
            image: Container image name (e.g., 'nginx:latest')
            
        Returns:
            Dictionary containing scan results
        """
        print(f"\n[*] Scanning image: {image}")
        print("-" * 50)
        
        cmd = [
            'trivy', 'image',
            '--format', 'json',
            '--severity', ','.join(self.severity_filter),
            image
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0 and not result.stdout:
                print(f"[!] Error scanning {image}: {result.stderr}")
                return {'error': result.stderr, 'image': image}
            
            return json.loads(result.stdout) if result.stdout else {}
            
        except subprocess.TimeoutExpired:
            print(f"[!] Timeout scanning {image}")
            return {'error': 'Scan timeout', 'image': image}
        except json.JSONDecodeError as e:
            print(f"[!] Error parsing results: {e}")
            return {'error': str(e), 'image': image}
    
    def summarize_results(self, results: Dict) -> Dict[str, int]:
        """
        Summarize vulnerability counts by severity.
        
        Args:
            results: Trivy scan results
            
        Returns:
            Dictionary with severity counts
        """
        summary = {level: 0 for level in self.SEVERITY_LEVELS}
        
        if 'Results' not in results:
            return summary
        
        for result in results.get('Results', []):
            for vuln in result.get('Vulnerabilities', []):
                severity = vuln.get('Severity', 'UNKNOWN')
                if severity in summary:
                    summary[severity] += 1
        
        return summary
    
    def print_report(self, image: str, results: Dict) -> None:
        """Print formatted vulnerability report."""
        print("\n" + "=" * 80)
        print("CONTAINER SECURITY SCAN REPORT")
        print(f"Image: {image}")
        print(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        
        if 'error' in results:
            print(f"\n[!] SCAN ERROR: {results['error']}")
            return
        
        summary = self.summarize_results(results)
        
        print("\nVULNERABILITY SUMMARY")
        print("-" * 20)
        for severity, count in summary.items():
            if count > 0 or severity in ['CRITICAL', 'HIGH']:
                indicator = "🔴" if severity == 'CRITICAL' else "🟠" if severity == 'HIGH' else "🟡"
                print(f"{indicator} {severity}: {count}")
        
        total = sum(summary.values())
        print(f"\nTotal Vulnerabilities: {total}")
        
        # Print critical and high findings
        if 'Results' in results:
            critical_high = []
            for result in results['Results']:
                for vuln in result.get('Vulnerabilities', []):
                    if vuln.get('Severity') in ['CRITICAL', 'HIGH']:
                        critical_high.append(vuln)
            
            if critical_high:
                print(f"\n{'CRITICAL/HIGH SEVERITY FINDINGS':^80}")
                print("-" * 80)
                for vuln in critical_high[:10]:  # Limit to first 10
                    print(f"\n[{vuln.get('Severity')}] {vuln.get('VulnerabilityID')}")
                    print(f"  Package: {vuln.get('PkgName')} {vuln.get('InstalledVersion')}")
                    if vuln.get('FixedVersion'):
                        print(f"  Fixed In: {vuln.get('FixedVersion')}")
                    if vuln.get('Title'):
                        print(f"  Title: {vuln.get('Title')[:70]}...")
                
                if len(critical_high) > 10:
                    print(f"\n... and {len(critical_high) - 10} more CRITICAL/HIGH findings")
    
    def scan_multiple(self, images: List[str]) -> Dict[str, Dict]:
        """
        Scan multiple container images.
        
        Args:
            images: List of image names
            
        Returns:
            Dictionary mapping image names to results
        """
        all_results = {}
        for image in images:
            results = self.scan_image(image)
            all_results[image] = results
            self.print_report(image, results)
        
        return all_results
    
    def has_critical_vulnerabilities(self, results: Dict) -> bool:
        """Check if results contain CRITICAL vulnerabilities."""
        summary = self.summarize_results(results)
        return summary.get('CRITICAL', 0) > 0


def main():
    parser = argparse.ArgumentParser(
        description='Container Security Scanner - Automated vulnerability scanning using Trivy'
    )
    parser.add_argument(
        '--image', '-i',
        help='Container image to scan (e.g., nginx:latest)'
    )
    parser.add_argument(
        '--file', '-f',
        help='File containing list of images (one per line)'
    )
    parser.add_argument(
        '--severity', '-s',
        default='CRITICAL,HIGH,MEDIUM',
        help='Comma-separated severity levels (default: CRITICAL,HIGH,MEDIUM)'
    )
    parser.add_argument(
        '--output', '-o',
        help='Output file for JSON results'
    )
    parser.add_argument(
        '--fail-on-vuln',
        action='store_true',
        help='Exit with code 1 if CRITICAL vulnerabilities found'
    )
    
    args = parser.parse_args()
    
    if not args.image and not args.file:
        parser.error("Either --image or --file is required")
    
    severity_filter = [s.strip().upper() for s in args.severity.split(',')]
    scanner = ContainerSecurityScanner(severity_filter=severity_filter)
    
    images = []
    if args.image:
        images.append(args.image)
    if args.file:
        with open(args.file, 'r') as f:
            images.extend([line.strip() for line in f if line.strip()])
    
    all_results = scanner.scan_multiple(images)
    
    # Save JSON output if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(all_results, f, indent=2)
        print(f"\n[+] Results saved to: {args.output}")
    
    # Check for critical vulnerabilities if --fail-on-vuln
    if args.fail_on_vuln:
        for image, results in all_results.items():
            if scanner.has_critical_vulnerabilities(results):
                print(f"\n[!] CRITICAL vulnerabilities found in {image}")
                sys.exit(1)
    
    print("\n[+] Scan complete!")


if __name__ == '__main__':
    main()
