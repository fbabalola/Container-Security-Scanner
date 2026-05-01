#!/usr/bin/env python3
"""
CIS Docker Benchmark Checks
Quick validation script for container security settings

Run this against a Dockerfile or running container to check for common issues.

Author: Firebami Babalola
"""

import subprocess
import sys
import re
import argparse
from pathlib import Path


def print_check(check_id: str, description: str, passed: bool, details: str = ""):
    """Print a formatted check result."""
    status = "✅ PASS" if passed else "❌ FAIL"
    print(f"\n[{check_id}] {description}")
    print(f"  Status: {status}")
    if details:
        print(f"  Details: {details}")


def check_dockerfile(dockerfile_path: str) -> dict:
    """
    Check a Dockerfile against CIS Docker Benchmark recommendations.
    
    Based on CIS Docker Benchmark v1.6.0
    """
    results = {"passed": 0, "failed": 0, "checks": []}
    
    with open(dockerfile_path, 'r') as f:
        content = f.read()
        lines = content.split('\n')
    
    print("=" * 70)
    print(f"CIS DOCKER BENCHMARK - DOCKERFILE ANALYSIS")
    print(f"File: {dockerfile_path}")
    print("=" * 70)
    
    # -------------------------------------------------------------------------
    # 4.1 - Create a user for the container
    # -------------------------------------------------------------------------
    has_user = bool(re.search(r'^USER\s+(?!root)', content, re.MULTILINE))
    print_check(
        "4.1",
        "Ensure a user for the container has been created",
        has_user,
        "Found non-root USER directive" if has_user else "No USER directive or running as root"
    )
    if has_user:
        results["passed"] += 1
    else:
        results["failed"] += 1
    
    # -------------------------------------------------------------------------
    # 4.2 - Use trusted base images
    # -------------------------------------------------------------------------
    from_lines = re.findall(r'^FROM\s+(.+)$', content, re.MULTILINE)
    using_latest = any(':latest' in img or (':' not in img and '@' not in img) for img in from_lines)
    print_check(
        "4.2",
        "Ensure base image uses specific version tag",
        not using_latest,
        f"Base images: {', '.join(from_lines)}" if not using_latest else "Using :latest or untagged image"
    )
    if not using_latest:
        results["passed"] += 1
    else:
        results["failed"] += 1
    
    # -------------------------------------------------------------------------
    # 4.3 - Do not install unnecessary packages
    # -------------------------------------------------------------------------
    # Check for common unnecessary packages
    unnecessary = ['vim', 'nano', 'curl', 'wget', 'netcat', 'nmap', 'telnet', 'ssh']
    found_unnecessary = []
    for pkg in unnecessary:
        # Look for apt install, apk add, yum install with these packages
        if re.search(rf'\b{pkg}\b', content):
            found_unnecessary.append(pkg)
    
    print_check(
        "4.3",
        "Avoid installing unnecessary packages",
        len(found_unnecessary) == 0,
        f"Found potentially unnecessary: {', '.join(found_unnecessary)}" if found_unnecessary else "No obvious unnecessary packages"
    )
    if len(found_unnecessary) == 0:
        results["passed"] += 1
    else:
        results["failed"] += 1
    
    # -------------------------------------------------------------------------
    # 4.6 - Add HEALTHCHECK instruction
    # -------------------------------------------------------------------------
    has_healthcheck = 'HEALTHCHECK' in content
    print_check(
        "4.6",
        "Ensure HEALTHCHECK instruction is added",
        has_healthcheck,
        "HEALTHCHECK found" if has_healthcheck else "No HEALTHCHECK instruction"
    )
    if has_healthcheck:
        results["passed"] += 1
    else:
        results["failed"] += 1
    
    # -------------------------------------------------------------------------
    # 4.7 - Do not use update instructions alone
    # -------------------------------------------------------------------------
    # apt-get update should be followed by install in same RUN
    update_alone = bool(re.search(r'RUN\s+apt-get\s+update\s*$', content, re.MULTILINE))
    print_check(
        "4.7",
        "Ensure update and install are combined in single RUN",
        not update_alone,
        "Update combined with install" if not update_alone else "apt-get update in standalone RUN"
    )
    if not update_alone:
        results["passed"] += 1
    else:
        results["failed"] += 1
    
    # -------------------------------------------------------------------------
    # 4.9 - Use COPY instead of ADD
    # -------------------------------------------------------------------------
    # ADD has extra features (URL download, tar extraction) that can be security risks
    uses_add = bool(re.search(r'^ADD\s+', content, re.MULTILINE))
    print_check(
        "4.9",
        "Use COPY instead of ADD",
        not uses_add,
        "Using COPY only" if not uses_add else "ADD instruction found (use COPY unless you need ADD features)"
    )
    if not uses_add:
        results["passed"] += 1
    else:
        results["failed"] += 1
    
    # -------------------------------------------------------------------------
    # 4.10 - Do not store secrets in Dockerfiles
    # -------------------------------------------------------------------------
    secret_patterns = [
        r'(password|passwd|pwd)\s*[=:]\s*["\']?.+["\']?',
        r'(api[_-]?key|apikey)\s*[=:]\s*["\']?.+["\']?',
        r'(secret|token)\s*[=:]\s*["\']?.+["\']?',
        r'AWS_SECRET_ACCESS_KEY',
        r'PRIVATE[_-]?KEY'
    ]
    secrets_found = []
    for pattern in secret_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            secrets_found.extend(matches)
    
    print_check(
        "4.10",
        "Do not store secrets in Dockerfiles",
        len(secrets_found) == 0,
        "No obvious secrets found" if len(secrets_found) == 0 else f"Possible secrets: {secrets_found[:3]}"
    )
    if len(secrets_found) == 0:
        results["passed"] += 1
    else:
        results["failed"] += 1
    
    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    total = results["passed"] + results["failed"]
    print(f"Passed: {results['passed']}/{total}")
    print(f"Failed: {results['failed']}/{total}")
    
    if results["failed"] > 0:
        print("\n⚠️  Address failed checks before deploying to production")
    else:
        print("\n✅ All basic checks passed")
    
    return results


def check_running_container(container_id: str) -> dict:
    """
    Check a running container against CIS benchmarks.
    Uses docker inspect to examine container configuration.
    """
    results = {"passed": 0, "failed": 0}
    
    try:
        # Get container inspect data
        cmd = ['docker', 'inspect', container_id]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        import json
        config = json.loads(result.stdout)[0]
    except subprocess.CalledProcessError as e:
        print(f"Error inspecting container: {e}")
        return results
    except json.JSONDecodeError:
        print("Error parsing container config")
        return results
    
    print("=" * 70)
    print(f"CIS DOCKER BENCHMARK - CONTAINER ANALYSIS")
    print(f"Container: {container_id}")
    print("=" * 70)
    
    # -------------------------------------------------------------------------
    # 5.4 - Ensure privileged containers are not used
    # -------------------------------------------------------------------------
    privileged = config.get('HostConfig', {}).get('Privileged', False)
    print_check(
        "5.4",
        "Ensure privileged containers are not used",
        not privileged,
        "Not running privileged" if not privileged else "Container is PRIVILEGED - major security risk"
    )
    if not privileged:
        results["passed"] += 1
    else:
        results["failed"] += 1
    
    # -------------------------------------------------------------------------
    # 5.7 - Ensure unnecessary ports are not mapped
    # -------------------------------------------------------------------------
    ports = config.get('NetworkSettings', {}).get('Ports', {})
    exposed_ports = [p for p in ports if ports[p] is not None]
    print_check(
        "5.7",
        "Review exposed ports",
        True,  # Informational - can't auto-determine if necessary
        f"Exposed ports: {', '.join(exposed_ports) if exposed_ports else 'None'}"
    )
    
    # -------------------------------------------------------------------------
    # 5.9 - Ensure host network is not shared
    # -------------------------------------------------------------------------
    network_mode = config.get('HostConfig', {}).get('NetworkMode', '')
    using_host_network = network_mode == 'host'
    print_check(
        "5.9",
        "Ensure host network is not shared",
        not using_host_network,
        "Using bridge/custom network" if not using_host_network else "Using HOST network - container can see all host traffic"
    )
    if not using_host_network:
        results["passed"] += 1
    else:
        results["failed"] += 1
    
    # -------------------------------------------------------------------------
    # 5.10 - Limit container memory
    # -------------------------------------------------------------------------
    memory_limit = config.get('HostConfig', {}).get('Memory', 0)
    has_memory_limit = memory_limit > 0
    print_check(
        "5.10",
        "Ensure memory is limited for containers",
        has_memory_limit,
        f"Memory limit: {memory_limit / (1024*1024):.0f}MB" if has_memory_limit else "No memory limit set"
    )
    if has_memory_limit:
        results["passed"] += 1
    else:
        results["failed"] += 1
    
    # -------------------------------------------------------------------------
    # 5.12 - Ensure root filesystem is mounted read-only
    # -------------------------------------------------------------------------
    read_only = config.get('HostConfig', {}).get('ReadonlyRootfs', False)
    print_check(
        "5.12",
        "Ensure root filesystem is mounted read-only",
        read_only,
        "Root filesystem is read-only" if read_only else "Root filesystem is writable"
    )
    if read_only:
        results["passed"] += 1
    else:
        results["failed"] += 1
    
    # -------------------------------------------------------------------------
    # 5.25 - Ensure container is running as non-root
    # -------------------------------------------------------------------------
    user = config.get('Config', {}).get('User', '')
    running_as_nonroot = bool(user) and user != '0' and user.lower() != 'root'
    print_check(
        "5.25",
        "Ensure container runs as non-root user",
        running_as_nonroot,
        f"Running as user: {user}" if user else "Running as root"
    )
    if running_as_nonroot:
        results["passed"] += 1
    else:
        results["failed"] += 1
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    total = results["passed"] + results["failed"]
    print(f"Passed: {results['passed']}/{total}")
    print(f"Failed: {results['failed']}/{total}")
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description='CIS Docker Benchmark Checks'
    )
    parser.add_argument(
        '--dockerfile', '-d',
        help='Path to Dockerfile to analyze'
    )
    parser.add_argument(
        '--container', '-c',
        help='Running container ID or name to analyze'
    )
    
    args = parser.parse_args()
    
    if not args.dockerfile and not args.container:
        parser.error("Specify --dockerfile or --container")
    
    if args.dockerfile:
        check_dockerfile(args.dockerfile)
    
    if args.container:
        check_running_container(args.container)


if __name__ == '__main__':
    main()
