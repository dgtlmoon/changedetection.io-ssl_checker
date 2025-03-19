#!/usr/bin/env python3
"""
Test script to evaluate the cert.py module against known problematic certificates
using the badssl.com test domains.
"""

import sys
import os
import ssl
import json
import socket
import time
from pprint import pprint

# Import the cert.py module from the current directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cert import get_certificate_details, format_certificate_info

# List of badssl.com test domains and expected issues
TEST_DOMAINS = [
    {
        "url": "badssl.com",
        "description": "Valid certificate (control)",
        "expected_issues": [],
    },
    {
        "url": "expired.badssl.com",
        "description": "Expired certificate",
        "expected_issues": ["expired", "days_remaining <= 0"],
    },
    {
        "url": "wrong.host.badssl.com",
        "description": "Certificate with wrong hostname",
        "expected_issues": ["hostname mismatch", "common name"],
    },
    {
        "url": "self-signed.badssl.com",
        "description": "Self-signed certificate",
        "expected_issues": ["self_signed", "trusted_by_browsers = False"],
    },
    {
        "url": "untrusted-root.badssl.com",
        "description": "Certificate with untrusted root",
        "expected_issues": ["trusted_by_browsers = False", "chain_valid = No"],
    },
    {
        "url": "revoked.badssl.com",
        "description": "Revoked certificate",
        "expected_issues": ["revoked", "OCSP"],
    },
    {
        "url": "pinning-test.badssl.com",
        "description": "Certificate pinning test",
        "expected_issues": [], # This should be a valid cert, but might trigger pinning warnings in some contexts
    },
]

def test_domain(domain_info, verbose=False):
    """Test a specific domain and check if expected issues are detected."""
    url = domain_info["url"]
    description = domain_info["description"]
    expected_issues = domain_info["expected_issues"]
    
    print(f"\n{'=' * 70}")
    print(f"Testing: {url}")
    print(f"Description: {description}")
    print(f"Expected issues: {', '.join(expected_issues) if expected_issues else 'None'}")
    print('-' * 70)
    
    try:
        # Get the certificate details with verification disabled to allow testing of bad certs
        cert_details = get_certificate_details(url, verify=False)
        
        # Format the results for display
        formatted_info = format_certificate_info(cert_details)
        
        # Check if expected issues are found in the formatted output or certificate details
        issues_found = []
        issues_missed = []
        
        for issue in expected_issues:
            # Check in formatted information
            if issue.lower() in formatted_info.lower():
                issues_found.append(issue)
                continue
                
            # Check specific certificate properties
            issue_found = False
            if issue == "days_remaining <= 0" and cert_details['days_remaining'] <= 0:
                issue_found = True
            elif issue == "self_signed" and cert_details['self_signed']:
                issue_found = True
            elif issue == "trusted_by_browsers = False" and not cert_details['trusted_by_browsers']:
                issue_found = True
            elif issue == "chain_valid = No" and cert_details['certificate_chain']['chain_valid'] == "No":
                issue_found = True
                
            if issue_found:
                issues_found.append(issue)
            else:
                issues_missed.append(issue)
        
        # Print results
        if verbose:
            print(formatted_info)
        else:
            # Extract and display key findings
            key_findings = [
                f"Valid until: {cert_details['not_after']}",
                f"Days remaining: {cert_details['days_remaining']}",
                f"Self-signed: {'YES' if cert_details['self_signed'] else 'NO'}",
                f"Browser trusted: {'YES' if cert_details['trusted_by_browsers'] else 'NO'}"
            ]
            
            # Add TLS version support
            tls_versions = [f"{v}: {'Supported' if s else 'Not Supported'}" 
                           for v, s in cert_details['tls_versions'].items()]
            key_findings.append("TLS versions: " + ", ".join(tls_versions))
            
            # Add chain information
            chain_info = cert_details['certificate_chain']
            key_findings.append(f"Chain length: {chain_info['chain_length']}")
            key_findings.append(f"Chain complete: {chain_info['chain_complete']}")
            key_findings.append(f"Chain valid: {chain_info['chain_valid']}")
            
            # Add revocation status
            key_findings.append(f"OCSP Status: {cert_details['revocation_status']}")
            
            print("\nKey Findings:")
            for finding in key_findings:
                print(f"- {finding}")
        
        # Summarize issue detection
        print("\nIssue Detection:")
        if not expected_issues:
            print("- No issues expected, and none should be reported")
        else:
            if issues_found:
                print(f"- DETECTED ({len(issues_found)}/{len(expected_issues)}): {', '.join(issues_found)}")
            if issues_missed:
                print(f"- MISSED ({len(issues_missed)}/{len(expected_issues)}): {', '.join(issues_missed)}")
            
            # Overall result
            success_rate = len(issues_found) / len(expected_issues) if expected_issues else 1.0
            print(f"\nSuccess rate: {success_rate * 100:.1f}%")
            
    except Exception as e:
        print(f"\nERROR: {str(e)}")
        return False
    
    return True

def main():
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    specific_domain = None
    
    # Check if a specific domain was requested
    for arg in sys.argv[1:]:
        if not arg.startswith("-"):
            specific_domain = arg
            break
    
    if specific_domain:
        # Test only the specified domain
        for domain in TEST_DOMAINS:
            if specific_domain.lower() in domain["url"].lower():
                test_domain(domain, verbose)
                break
        else:
            print(f"Domain '{specific_domain}' not found in test list.")
            print("Available domains:")
            for domain in TEST_DOMAINS:
                print(f"- {domain['url']} ({domain['description']})")
    else:
        # Test all domains
        results = []
        for domain in TEST_DOMAINS:
            success = test_domain(domain, verbose)
            results.append({
                "domain": domain["url"],
                "success": success
            })
            # Add a short delay between tests
            time.sleep(1)
        
        # Summarize all results
        print("\n" + "=" * 70)
        print("SUMMARY OF ALL TESTS")
        print("-" * 70)
        success_count = sum(1 for r in results if r["success"])
        print(f"Total tests: {len(results)}")
        print(f"Successful tests: {success_count}")
        print(f"Failed tests: {len(results) - success_count}")

if __name__ == "__main__":
    print("BadSSL Certificate Testing Tool")
    print("This script tests cert.py against various problematic certificates.")
    print("Usage: python test_badssl.py [domain] [--verbose|-v]")
    print("If no domain is specified, all test domains will be checked.")
    main()