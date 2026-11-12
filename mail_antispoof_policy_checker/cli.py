"""
Mail AntiSpoof Policy Checker - CLI Tool

Command-line interface for checking SPF, DKIM, and DMARC records
and analyzing unknown SPF data.
"""

import argparse
import asyncio
import concurrent.futures
import contextlib
import json
import os
import sys
import csv
import pandas as pd
from datetime import datetime
from pathlib import Path

from lib.checkers.spf_checker import SPFChecker
from lib.checkers.dmarc_checker import DMARCChecker
from lib.checkers.dkim_checker import DKIMChecker
from lib.checkers.unregistered_domain_checker import (
    check_domains_availability,
    collect_spf_include_sources,
    apply_spf_include_availability,
    collect_cname_registration_candidates,
    apply_cname_registration_results,
    _CHECKER_AVAILABLE as _DOMAIN_CHECKER_AVAILABLE,
    _CHECKER_IMPORT_ERROR as _DOMAIN_CHECKER_IMPORT_ERROR,
)
from lib.analyzers.unknown_data_analyzer import check_unknown_spf_data
from lib.data.loaders import DataLoaders
from lib.utils.maxmind_client import MaxMindClient, InvalidLicenseKeyError
from lib.utils.email_domain_checker import EmailDomainChecker
from lib.utils.async_dns_resolver import AsyncPooledDNSResolver
from lib.utils.factordb import FactorDBClient


def convert_json_report_to_excel(json_path: str, excel_path: str = None) -> str:
    """
    Convert a JSON report file to Excel format.

    Args:
        json_path: Path to the JSON report file
        excel_path: Optional path for the output Excel file. If not provided,
                   uses the same path as JSON but with .xlsx extension.

    Returns:
        Path to the created Excel file
    """
    # Load JSON data
    with open(json_path, 'r', encoding='utf-8') as f:
        all_results = json.load(f)

    # Determine output path
    if excel_path is None:
        excel_path = json_path.rsplit('.', 1)[0] + '.xlsx'

    # Detect which check types are present in the data
    has_spf = any('spf' in result for result in all_results)
    has_dmarc = any('dmarc' in result for result in all_results)
    has_dkim = any('dkim' in result for result in all_results)

    with pd.ExcelWriter(excel_path, engine='openpyxl') as writer:
        # Summary sheet
        summary_data = []
        for result in all_results:
            row = {
                'Record ID': result['record_id'],
                'Domain': result.get('domain', ''),
                'Email Domain Indicators': ', '.join(result.get('email_domain_indicators', []))
            }

            if 'spf' in result:
                spf = result['spf']
                if 'error' in spf:
                    row['SPF Status'] = 'Error'
                    row['SPF Issues'] = spf['error']
                else:
                    row['SPF Status'] = 'OK' if len(spf.get('issues', [])) == 0 else 'Issues'
                    row['SPF Issues'] = len(spf.get('issues', []))
                    row['SPF Includes'] = len(spf.get('all_includes', []))
                    row['SPF IP Addresses Count'] = len(spf.get('all_ip_addresses', []))

            if 'dmarc' in result:
                dmarc = result['dmarc']
                if 'error' in dmarc:
                    row['DMARC Status'] = 'Error'
                    row['DMARC Policy'] = dmarc['error']
                else:
                    row['DMARC Status'] = 'OK' if len(dmarc.get('issues', [])) == 0 else 'Issues'
                    row['DMARC Policy'] = dmarc.get('policy', 'N/A')
                    row['DMARC Issues'] = len(dmarc.get('issues', []))

            if 'dkim' in result:
                dkim = result['dkim']
                if 'error' in dkim:
                    row['DKIM Status'] = 'Error'
                else:
                    row['DKIM Status'] = 'OK' if len(dkim.get('issues', [])) == 0 else 'Issues'
                    row['DKIM Issues'] = len(dkim.get('issues', []))

            summary_data.append(row)

        df_summary = pd.DataFrame(summary_data)
        df_summary.to_excel(writer, sheet_name='Summary', index=False)

        # SPF Records sheet
        if has_spf:
            spf_records_data = []
            for result in all_results:
                if 'spf' in result and 'error' not in result['spf']:
                    spf = result['spf']
                    spf_records_data.append({
                        'Record ID': result['record_id'],
                        'Domain': result.get('domain', ''),
                        'SPF Record': spf.get('spf_record', ''),
                        'ALL Qualifier': spf.get('all_qualifier', 'N/A'),
                        'Includes Count': len(spf.get('all_includes', [])),
                        'IP Addresses Count': len(spf.get('all_ip_addresses', [])),
                        'Issues Count': len(spf.get('issues', []))
                    })

            if spf_records_data:
                df_spf_records = pd.DataFrame(spf_records_data)
                df_spf_records.to_excel(writer, sheet_name='SPF Records', index=False)

        # DMARC Records sheet
        if has_dmarc:
            dmarc_records_data = []
            for result in all_results:
                if 'dmarc' in result and 'error' not in result['dmarc']:
                    dmarc = result['dmarc']
                    if dmarc.get('dmarc_record'):
                        dmarc_records_data.append({
                            'Record ID': result['record_id'],
                            'Domain': result.get('domain', ''),
                            'DMARC Domain Checked': dmarc.get('dmarc_domain_checked', ''),
                            'DMARC Record': dmarc.get('dmarc_record', ''),
                            'Policy': dmarc.get('policy', 'N/A'),
                            'Subdomain Policy': dmarc.get('subdomain_policy', 'N/A'),
                            'Percentage': dmarc.get('percentage', 'N/A'),
                            'Issues Count': len(dmarc.get('issues', []))
                        })

            if dmarc_records_data:
                df_dmarc_records = pd.DataFrame(dmarc_records_data)
                df_dmarc_records.to_excel(writer, sheet_name='DMARC Records', index=False)

        # DKIM Records sheet
        if has_dkim:
            dkim_records_data = []
            for result in all_results:
                if 'dkim' in result and 'error' not in result['dkim']:
                    dkim = result['dkim']
                    selectors_found = dkim.get('selectors_found', [])
                    if selectors_found:
                        for selector_info in selectors_found:
                            dkim_records_data.append({
                                'Record ID': result['record_id'],
                                'Domain': result.get('domain', ''),
                                'Selector': selector_info.get('selector', 'N/A'),
                                'DKIM Record': selector_info.get('dkim_record', ''),
                                'Key Type': selector_info.get('key_type', 'N/A'),
                                'Key Size': selector_info.get('key_size', 'N/A')
                            })

            if dkim_records_data:
                df_dkim_records = pd.DataFrame(dkim_records_data)
                df_dkim_records.to_excel(writer, sheet_name='DKIM Records', index=False)

        # SPF Issues sheet
        if has_spf:
            spf_details = []
            for result in all_results:
                if 'spf' in result and 'error' not in result['spf']:
                    spf = result['spf']
                    for issue in spf.get('issues', []):
                        additional_data = issue.get('additional_data', {})

                        # Format resolution path: join with " > "
                        resolution_path = issue.get('resolution_path', [])
                        resolution_path_str = ' > '.join(resolution_path) if resolution_path else ''

                        row = {
                            'Record ID': result['record_id'],
                            'Domain': result.get('domain', ''),
                            'Resolution Path': resolution_path_str,
                            'Severity': issue.get('severity', 'N/A'),
                            'Category': issue.get('category', 'N/A'),
                            'Title': issue.get('title', 'N/A')
                        }

                        # Add Service Name right after Title if available
                        service_name = additional_data.get('service_name', '')
                        if service_name:
                            row['Service Name'] = service_name

                        # Add Email Domain Indicators
                        email_indicators = result.get('email_domain_indicators', [])
                        if email_indicators:
                            row['Email Domain Indicators'] = ', '.join(email_indicators)

                        # Add detailed columns based on issue type
                        if 'include' in additional_data:
                            row['Include'] = additional_data['include']
                            if 'registered_domain' in additional_data:
                                row['Domain To Buy'] = additional_data['registered_domain']
                        elif 'chain' in additional_data:
                            row['CNAME Chain'] = ' -> '.join(additional_data['chain'])
                            row['Domain To Buy'] = additional_data.get('registrable_domain', '')
                        elif 'ip_range' in additional_data:
                            row['IP Range'] = additional_data['ip_range']
                            if 'match_type' in additional_data:
                                row['Match Type'] = additional_data['match_type']
                            if 'dangerous_range' in additional_data:
                                row['Dangerous Range'] = additional_data['dangerous_range']
                            if 'overlap_start' in additional_data and additional_data['overlap_start']:
                                row['Overlap Start'] = additional_data['overlap_start']
                            if 'overlap_end' in additional_data and additional_data['overlap_end']:
                                row['Overlap End'] = additional_data['overlap_end']
                            if 'overlap_count' in additional_data and additional_data['overlap_count']:
                                row['Overlap Count'] = additional_data['overlap_count']
                        elif 'ip' in additional_data:
                            row['IP Address'] = additional_data['ip']
                            if 'as_organization' in additional_data:
                                row['AS Organization'] = additional_data['as_organization']

                        spf_details.append(row)

            if spf_details:
                df_spf = pd.DataFrame(spf_details)
                df_spf.to_excel(writer, sheet_name='SPF Issues', index=False)

        # DMARC Issues sheet
        if has_dmarc:
            dmarc_details = []
            for result in all_results:
                if 'dmarc' in result and 'error' not in result['dmarc']:
                    dmarc = result['dmarc']
                    for issue in dmarc.get('issues', []):
                        additional_data = issue.get('additional_data', {})

                        row = {
                            'Record ID': result['record_id'],
                            'Domain': result.get('domain', ''),
                            'Severity': issue.get('severity', 'N/A'),
                            'Category': issue.get('category', 'N/A'),
                            'Title': issue.get('title', 'N/A')
                        }

                        if 'dmarc_domain_checked' in dmarc:
                            row['DMARC Domain'] = dmarc['dmarc_domain_checked']

                        email_indicators = result.get('email_domain_indicators', [])
                        if email_indicators:
                            row['Email Domain Indicators'] = ', '.join(email_indicators)

                        if 'policy' in additional_data:
                            row['Policy'] = additional_data['policy']
                        if 'subdomain_policy' in additional_data:
                            row['Subdomain Policy'] = additional_data['subdomain_policy']
                        if 'percentage' in additional_data:
                            row['Percentage'] = additional_data['percentage']
                        if 'chain' in additional_data:
                            row['CNAME Chain'] = ' -> '.join(additional_data['chain'])
                            row['Domain To Buy'] = additional_data.get('registrable_domain', '')

                        dmarc_details.append(row)

            if dmarc_details:
                df_dmarc = pd.DataFrame(dmarc_details)
                df_dmarc.to_excel(writer, sheet_name='DMARC Issues', index=False)

        # DKIM Issues sheet
        if has_dkim:
            dkim_details = []
            for result in all_results:
                if 'dkim' in result and 'error' not in result['dkim']:
                    dkim = result['dkim']
                    for issue in dkim.get('issues', []):
                        additional_data = issue.get('additional_data', {})
                        row = {
                            'Record ID': result['record_id'],
                            'Domain': result.get('domain', ''),
                            'Severity': issue.get('severity', 'N/A'),
                            'Category': issue.get('category', 'N/A'),
                            'Title': issue.get('title', 'N/A'),
                            'Selector': additional_data.get('selector')
                                        or ', '.join(additional_data.get('selectors', [])),
                            'Key Size': additional_data.get('key_size', ''),
                            'CNAME Chain': ' -> '.join(additional_data.get('chain', [])),
                            'Domain To Buy': additional_data.get('registrable_domain', ''),
                            'Detail': issue.get('detail', ''),
                        }
                        email_indicators = result.get('email_domain_indicators', [])
                        if email_indicators:
                            row['Email Domain Indicators'] = ', '.join(email_indicators)
                        dkim_details.append(row)

            if dkim_details:
                pd.DataFrame(dkim_details).to_excel(writer, sheet_name='DKIM Issues', index=False)

    return excel_path


def get_unique_output_filename(output_dir: str, base_filename: str) -> str:
    """
    Prompt user for output filename until a unique one is provided.

    Args:
        output_dir: Output directory
        base_filename: Suggested base filename

    Returns:
        Unique filename
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Try base filename first
    output_path = os.path.join(output_dir, base_filename)
    if not os.path.exists(output_path):
        return base_filename

    # File exists, prompt user
    print(f"\nFile '{base_filename}' already exists in {output_dir}/")
    while True:
        user_input = input("Enter a different filename (without path): ").strip()
        if not user_input:
            print("Filename cannot be empty. Please try again.")
            continue

        output_path = os.path.join(output_dir, user_input)
        if not os.path.exists(output_path):
            return user_input
        else:
            print(f"File '{user_input}' already exists. Please try a different name.")


async def _process_domains_async(domains_to_check, checkers, email_domain_checker, args):
    """Async domain processing loop used when --async-mode is active.

    Runs all per-domain checks concurrently using asyncio.to_thread(), with
    concurrency limited by --max-concurrent (0 = unlimited).  Results are
    collected in input order.

    Args:
        domains_to_check: List of domain entries (strings or dicts).
        checkers: Dict with 'spf', 'dmarc', 'dkim' checker instances.
        email_domain_checker: EmailDomainChecker instance or None.
        args: Parsed CLI arguments.

    Returns:
        List of result dicts in the same order as domains_to_check.
    """
    total = len(domains_to_check)
    max_concurrent = getattr(args, 'max_concurrent', 50)

    # Ensure the thread pool is large enough to service all concurrent slots.
    loop = asyncio.get_running_loop()
    max_workers = max(64, (max_concurrent * 2) if max_concurrent > 0 else 128)
    loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(max_workers=max_workers))

    # Lazily initialise the NS-swap lock on SPFChecker (must happen inside the
    # running loop so the Lock belongs to the correct event loop).
    spf_ns_lock = None
    if 'spf' in checkers and getattr(checkers['spf'], 'use_ns_record', False):
        if checkers['spf']._ns_lock is None:
            checkers['spf']._ns_lock = asyncio.Lock()
        spf_ns_lock = checkers['spf']._ns_lock

    sem = asyncio.Semaphore(max_concurrent) if max_concurrent > 0 else None

    # Separate semaphore for EmailDomainChecker calls.
    # Each email check makes up to 4 DNS/network calls (MX, SPF, DMARC, SMTP).
    # Without this cap, max_concurrent=50 could fire ~200 simultaneous DNS
    # queries, causing the DNS server to rate-limit and drop responses for
    # otherwise-resolvable domains.
    _EMAIL_CHECK_CONCURRENCY = 10
    email_sem = asyncio.Semaphore(_EMAIL_CHECK_CONCURRENCY)

    print_lock = asyncio.Lock()

    async def _process_one(i_0based, entry):
        i = i_0based + 1
        ctx_sem = sem if sem is not None else contextlib.nullcontext()
        async with ctx_sem:
            # ── Parse entry ───────────────────────────────────────────────
            if isinstance(entry, str):
                domain = entry
                record_id = domain
            elif isinstance(entry, dict) and 'domain' in entry:
                domain = entry['domain']
                record_id = domain
            elif isinstance(entry, dict) and 'record_id' in entry:
                record_id = entry['record_id']
                domain = record_id
            else:
                async with print_lock:
                    print(f"\n[{i}/{total}] Skipping invalid entry")
                return None

            # ── Email domain indicators ───────────────────────────────────
            email_indicators = []
            if email_domain_checker:
                try:
                    async with email_sem:
                        email_indicators = await asyncio.to_thread(
                            email_domain_checker.check, domain
                        )
                except Exception:
                    pass

            # Organizational-parent entries are DMARC-only: their SPF/DKIM are not
            # the leverage (the subdomain's are), only the parent's governing policy.
            parent_only = isinstance(entry, dict) and bool(entry.get('_org_parent_dmarc_only'))

            result = {
                'record_id': record_id,
                'domain': domain,
                'email_domain_indicators': email_indicators,
            }
            if parent_only:
                result['org_parent_dmarc_only'] = True

            should_scan = email_indicators or args.skip_email_domain_indicators_check

            # ── SPF ───────────────────────────────────────────────────────
            if 'spf' in args.check_types and should_scan and not parent_only:
                try:
                    if args.spf_tree_json and isinstance(entry, dict) and 'parsed_spf' in entry:
                        spf_result = await asyncio.to_thread(
                            checkers['spf'].check_spf_tree,
                            entry['parsed_spf'], record_id
                        )
                    elif isinstance(entry, dict) and entry.get('spf_record'):
                        spf_result = await asyncio.to_thread(
                            checkers['spf'].check_record,
                            entry['spf_record'], record_id
                        )
                    else:
                        if spf_ns_lock is not None:
                            async with spf_ns_lock:
                                spf_result = await asyncio.to_thread(
                                    checkers['spf'].check, domain
                                )
                        else:
                            spf_result = await asyncio.to_thread(
                                checkers['spf'].check, domain
                            )
                    result['spf'] = spf_result.to_dict()
                except Exception as e:
                    result['spf'] = {'error': str(e)}

            # ── DMARC ─────────────────────────────────────────────────────
            # Parent-only entries always run DMARC (that is the whole point), even
            # when they have no email-domain indicators.
            if 'dmarc' in args.check_types and (should_scan or parent_only):
                try:
                    if args.spf_tree_json and isinstance(entry, dict) and 'parsed_dmarc' in entry:
                        dmarc_result = await asyncio.to_thread(
                            checkers['dmarc'].check_parsed_dmarc,
                            entry['parsed_dmarc'], record_id
                        )
                    else:
                        dmarc_result = await asyncio.to_thread(
                            checkers['dmarc'].check, domain
                        )
                    result['dmarc'] = dmarc_result.to_dict()
                except Exception as e:
                    result['dmarc'] = {'error': str(e)}

            # ── DKIM ──────────────────────────────────────────────────────
            if 'dkim' in args.check_types and not parent_only:
                try:
                    dkim_result = await asyncio.to_thread(
                        checkers['dkim'].check, domain
                    )
                    result['dkim'] = dkim_result.to_dict()
                except Exception as e:
                    result['dkim'] = {'error': str(e)}

            # ── Progress line ─────────────────────────────────────────────
            async with print_lock:
                parts = []
                if email_domain_checker:
                    ind_str = ', '.join(email_indicators) if email_indicators else 'None (non-email domain)'
                    parts.append(f"Email: {ind_str}")
                if 'spf' in result:
                    spf = result['spf']
                    if 'error' in spf:
                        parts.append(f"SPF: Error - {spf['error']}")
                    else:
                        parts.append(
                            f"SPF: {len(spf.get('issues', []))} issues, "
                            f"{len(spf.get('all_includes', []))} includes, "
                            f"{len(spf.get('all_ip_addresses', []))} IPs"
                        )
                if 'dmarc' in result:
                    dmarc = result['dmarc']
                    if 'error' in dmarc:
                        parts.append("DMARC: Error")
                    else:
                        parts.append(
                            f"DMARC: {len(dmarc.get('issues', []))} issues, "
                            f"Policy: {dmarc.get('policy', 'N/A')}"
                        )
                if 'dkim' in result:
                    dkim = result['dkim']
                    if 'error' in dkim:
                        parts.append("DKIM: Error")
                    else:
                        parts.append(f"DKIM: {len(dkim.get('issues', []))} issues")
                detail = " | ".join(parts)
                print(f"\n[{i}/{total}] {domain} - {detail}")

            return result

    raw = await asyncio.gather(
        *[_process_one(i, entry) for i, entry in enumerate(domains_to_check)],
        return_exceptions=True,
    )

    return [r for r in raw if r is not None and not isinstance(r, Exception)]


def run_check_record_mode(args):
    """
    Run check_record mode: Check SPF/DKIM/DMARC records from various input sources.

    Args:
        args: Parsed command-line arguments
    """
    print("=" * 80)
    print("Mail AntiSpoof Policy Checker - Record Checking Mode")
    print("=" * 80)

    # Initialize checkers based on --check-types
    checkers = {}
    data_loaders = None
    maxmind_client = None

    # Build the shared AsyncPooledDNSResolver used by all checkdmarc calls.
    # nameservers, timeout and rate limits must be configured here because
    # checkdmarc ignores its own nameservers/timeout kwargs when a resolver=
    # object is supplied.
    _resolver_ns = args.nameservers or None
    checkdmarc_resolver = AsyncPooledDNSResolver(
        nameservers=_resolver_ns,
        timeout=float(args.dns_timeout),
        max_global_concurrent=args.max_global_concurrent,
        max_per_nameserver=args.max_per_nameserver,
    )
    print(
        f"\n[DNS Resolver] pooled AsyncPooledDNSResolver — "
        f"global={args.max_global_concurrent}, per_ns={args.max_per_nameserver}, "
        f"timeout={args.dns_timeout}s, nameservers={checkdmarc_resolver.nameservers}"
    )

    if 'spf' in args.check_types:
        # Initialize DataLoaders and MaxMind for SPF
        data_loaders = DataLoaders(
            data_dir=args.data_dir,
            disable_ptr_blacklist=args.disable_ptr_blacklist,
            disable_update_ptr_blacklist=args.disable_update_ptr_blacklist,
            ptr_pool_size=args.ptr_blacklist_pool_size,
            nameservers=args.nameservers,
            dns_timeout=args.dns_timeout
        )

        try:
            data_loaders.load_all()
        except ValueError as e:
            print(f"\nERROR loading CSV data: {e}")
            sys.exit(1)

        print(f"\n[Data Loaded]")
        print(f"  Dangerous includes: {len(data_loaders.dangerous_includes)}")
        print(f"  Whitelisted includes: {len(data_loaders.whitelisted_includes)}")
        print(f"  Dangerous IP ranges: {len(data_loaders.dangerous_ip_ranges)}")
        print(f"  Third-party services: {len(data_loaders.third_party_services)}")

        # Warn if CSV files are missing
        if len(data_loaders.dangerous_includes) == 0:
            print(f"  Warning: Dangerous_SPF_Include.csv not found or empty - dangerous include checks disabled")
        if len(data_loaders.dangerous_ip_ranges) == 0:
            print(f"  Warning: Dangerous_SPF_Records_IP_Range.csv not found or empty - dangerous IP range checks disabled")
        if len(data_loaders.third_party_services) == 0:
            print(f"  Warning: Third_Party_Services_AS.csv not found or empty - AS organization checks disabled")

        # Initialize MaxMind if license key is set
        maxmind_license_key = os.environ.get('MAXMIND_LICENSE_KEY')
        if maxmind_license_key:
            try:
                # MaxMindClient validates key in __init__ by default
                maxmind_client = MaxMindClient.from_environment()
                print(f"  MaxMind client: Initialized (license key validated)")
            except InvalidLicenseKeyError as e:
                print(f"  MaxMind client: Disabled - Invalid license key: {e}")
                print(f"  Warning: AS Organization checks will be skipped")
            except Exception as e:
                print(f"  MaxMind client: Not initialized ({e})")
                print(f"  Warning: AS Organization checks will be skipped")
        else:
            print(f"  MaxMind client: Not configured (MAXMIND_LICENSE_KEY not set)")
            print(f"  Warning: AS Organization checks will be skipped")

        checkers['spf'] = SPFChecker(
            maxmind_client=maxmind_client,
            data_loaders=data_loaders,
            data_dir=args.data_dir,
            dns_timeout=args.dns_timeout,
            nameservers=args.nameservers,
            use_ns_record=args.use_ns_record,
            max_dns_retries=args.max_dns_retries,
            resolver=checkdmarc_resolver,
            cname_check=not args.skip_cname_check,
            cname_max_depth=args.cname_max_depth,
        )

    if 'dmarc' in args.check_types:
        checkers['dmarc'] = DMARCChecker(
            dns_timeout=args.dns_timeout,
            nameservers=args.nameservers,
            use_ns_record=args.use_ns_record,
            max_dns_retries=args.max_dns_retries,
            resolver=checkdmarc_resolver,
            cname_check=not args.skip_cname_check,
            cname_max_depth=args.cname_max_depth,
        )

    if 'dkim' in args.check_types:
        # Custom selector list (--dkim-selector-file) replaces the bundled one
        selector_file = args.dkim_selector_file or os.path.join(args.data_dir, 'DKIM_Selectors.txt')
        print(f"\n[DKIM Selectors]")
        print(f"  File: {selector_file}{'' if args.dkim_selector_file else ' (default)'}")
        try:
            n_selectors = len(DKIMChecker.load_selector_file(selector_file))
        except OSError as e:
            print(f"[ERROR] Cannot read DKIM selector file: {e}")
            return
        if n_selectors == 0:
            print(f"[ERROR] DKIM selector file contains no selector: {selector_file}")
            return
        print(f"  Loaded {n_selectors} selectors")
        checkers['dkim'] = DKIMChecker(
            selector_file=selector_file,
            dns_timeout=args.dns_timeout,
            nameservers=args.nameservers,
            max_dns_retries=args.max_dns_retries,
            cname_check=not args.skip_cname_check,
            cname_max_depth=args.cname_max_depth,
            wildcard_probes=args.cname_wildcard_probes,
            factordb=None if args.skip_factordb_check else FactorDBClient(),
        )

    if not args.skip_cname_check:
        print(f"\n[CNAME Check] Enabled on DKIM/DMARC/SPF lookup names "
              f"(max depth {args.cname_max_depth}, {max(3, args.cname_wildcard_probes)} wildcard probes)")

    # Read input domains/records
    domains_to_check = []

    if args.hostnames:
        # Read hostnames from file (one per line)
        print(f"\n[Input: Hostnames file]")
        print(f"  File: {args.hostnames}")

        if not os.path.exists(args.hostnames):
            print(f"[ERROR] File not found: {args.hostnames}")
            return

        try:
            with open(args.hostnames, 'r', encoding='utf-8') as f:
                domains_to_check = [line.strip() for line in f if line.strip()]
            print(f"  Loaded {len(domains_to_check)} domains")
        except Exception as e:
            print(f"[ERROR] Failed to read hostnames file: {e}")
            return

    elif args.check_spf_records:
        # Read CSV with domain;SPF columns (SPF ONLY mode)
        print(f"\n[Input: SPF Records CSV]")
        print(f"  File: {args.check_spf_records}")
        print(f"  Mode: SPF ONLY (ignoring --check-types)")

        if not os.path.exists(args.check_spf_records):
            print(f"[ERROR] File not found: {args.check_spf_records}")
            return

        try:
            with open(args.check_spf_records, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f, delimiter=';')
                for row in reader:
                    domain = row.get('domain', '').strip()
                    spf_record = row.get('SPF', '').strip()
                    if domain:
                        domains_to_check.append({
                            'domain': domain,
                            'spf_record': spf_record if spf_record else None
                        })
            print(f"  Loaded {len(domains_to_check)} SPF records")

            # Force check_types to SPF only
            args.check_types = ['spf']
        except Exception as e:
            print(f"[ERROR] Failed to read CSV file: {e}")
            return

    elif args.spf_tree_json:
        # Read JSON with parsed SPF trees (SPF ONLY mode)
        # Can be a file or a directory
        print(f"\n[Input: SPF Tree JSON]")
        print(f"  Path: {args.spf_tree_json}")
        print(f"  Mode: SPF ONLY (ignoring --check-types)")

        if not os.path.exists(args.spf_tree_json):
            print(f"[ERROR] Path not found: {args.spf_tree_json}")
            return

        try:
            # Check if it's a directory or a file
            if os.path.isdir(args.spf_tree_json):
                # Read all JSON files from directory
                json_files = [f for f in os.listdir(args.spf_tree_json) if f.endswith('.json')]
                if not json_files:
                    print(f"[ERROR] No JSON files found in directory: {args.spf_tree_json}")
                    return

                print(f"  Found {len(json_files)} JSON files in directory")
                for json_file in json_files:
                    file_path = os.path.join(args.spf_tree_json, json_file)
                    with open(file_path, 'r', encoding='utf-8') as f:
                        json_data = json.load(f)
                        if isinstance(json_data, list):
                            domains_to_check.extend(json_data)
                        else:
                            domains_to_check.append(json_data)
            else:
                # Read single JSON file
                with open(args.spf_tree_json, 'r', encoding='utf-8') as f:
                    json_data = json.load(f)
                domains_to_check = json_data if isinstance(json_data, list) else [json_data]

            print(f"  Loaded {len(domains_to_check)} parsed SPF records")

            # Force check_types to SPF only
            args.check_types = ['spf']
        except Exception as e:
            print(f"[ERROR] Failed to read JSON: {e}")
            return

    # Create EmailDomainChecker for email domain indicator detection
    email_domain_checker = None
    if not args.skip_email_domain_indicators_check:
        email_domain_checker = EmailDomainChecker(
            dns_timeout=args.dns_timeout,
            nameservers=args.nameservers,
            max_retries=args.max_dns_retries,
            required_indicators=args.require_indicators,
            available_checks=args.email_checks
        )

    # ── Organizational-parent DMARC (relaxed-alignment cross-domain spoofing) ──
    # DMARC is evaluated against the From-header domain and, by default, with relaxed
    # alignment: a spoof of From:@<parent> from a weak subdomain is governed by the
    # PARENT's own DMARC. Add each input subdomain's organizational (registrable)
    # parent as a DMARC-only target when not already present (deduplicated). DMARC
    # jumps straight to the organizational domain (no label-by-label walk).
    if 'dmarc' in args.check_types:
        from lib.utils.org_domains import derive_org_parents
        _entry_domains = []
        for _e in domains_to_check:
            if isinstance(_e, str):
                _entry_domains.append(_e)
            elif isinstance(_e, dict):
                _entry_domains.append(_e.get('domain') or _e.get('record_id') or '')
        _parents = derive_org_parents(_entry_domains)
        if _parents:
            print(f"  + {len(_parents)} organizational-parent domain(s) added for DMARC "
                  f"(relaxed-alignment check): {', '.join(_parents)}")
            for _p in _parents:
                domains_to_check.append({'domain': _p, '_org_parent_dmarc_only': True})

    print(f"\n[Processing {len(domains_to_check)} records...]")

    # ── Async mode ────────────────────────────────────────────────────────────
    if getattr(args, 'async_mode', False):
        if sys.version_info < (3, 9):
            print("[ERROR] --async-mode requires Python 3.9 or later.")
            return
        max_c = getattr(args, 'max_concurrent', 50)
        unlimited = "(unlimited)" if max_c == 0 else f"(max {max_c} concurrent)"
        print(f"  Mode: ASYNC {unlimited}")
        all_results = asyncio.run(
            _process_domains_async(domains_to_check, checkers, email_domain_checker, args)
        )
        _sync_entries: list = []
    else:
        # ── Sync mode (default) ───────────────────────────────────────────────
        all_results = []
        _sync_entries = domains_to_check

    for i, entry in enumerate(_sync_entries, 1):
        # Handle different input formats
        if isinstance(entry, str):
            # Hostname string
            domain = entry
            record_id = domain
            print(f"\n[{i}/{len(domains_to_check)}] Checking {domain}")
        elif isinstance(entry, dict) and 'domain' in entry:
            # CSV entry with domain and optional SPF record
            domain = entry['domain']
            record_id = domain
            print(f"\n[{i}/{len(domains_to_check)}] Checking {domain}")
        elif isinstance(entry, dict) and 'record_id' in entry:
            # JSON SPF tree entry
            record_id = entry['record_id']
            domain = record_id
            print(f"\n[{i}/{len(domains_to_check)}] Processing {record_id}")
        else:
            print(f"\n[{i}/{len(domains_to_check)}] Skipping invalid entry")
            continue

        # Determine email domain indicators FIRST (before any scanning)
        email_indicators = []
        if email_domain_checker:
            email_indicators = email_domain_checker.check(domain)

        # Organizational-parent entries are DMARC-only (see async path).
        parent_only = isinstance(entry, dict) and bool(entry.get('_org_parent_dmarc_only'))

        result = {
            'record_id': record_id,
            'domain': domain,
            'email_domain_indicators': email_indicators  # Store as list
        }
        if parent_only:
            result['org_parent_dmarc_only'] = True

        # Display email domain indicators
        if email_domain_checker:
            if email_indicators:
                print(f"  Email Domain Indicators: {', '.join(email_indicators)}")
            else:
                print(f"  Email Domain Indicators: None (non-email domain)")

        # Check SPF (ONLY if domain is used for email OR if skip flag is set)
        should_scan = email_indicators or args.skip_email_domain_indicators_check
        if 'spf' in args.check_types and should_scan and not parent_only:
            try:
                if args.spf_tree_json and 'parsed_spf' in entry:
                    # Use parsed SPF tree
                    spf_result = checkers['spf'].check_spf_tree(
                        entry['parsed_spf'],
                        record_id=record_id
                    )
                elif isinstance(entry, dict) and entry.get('spf_record'):
                    # Use provided SPF record string
                    spf_result = checkers['spf'].check_record(
                        entry['spf_record'],
                        record_id=record_id
                    )
                else:
                    # Query DNS
                    spf_result = checkers['spf'].check(domain)

                result['spf'] = spf_result.to_dict()
                print(f"  SPF: {len(spf_result.issues)} issues, {len(spf_result.all_includes)} includes, "
                      f"{len(spf_result.all_ip_addresses)} IPs")
            except Exception as e:
                result['spf'] = {'error': str(e)}
                print(f"  SPF: Error - {e}")

        # Check DMARC (ONLY if domain is used for email OR if skip flag is set;
        # organizational-parent entries always run DMARC).
        if 'dmarc' in args.check_types and (should_scan or parent_only):
            try:
                if args.spf_tree_json and 'parsed_dmarc' in entry:
                    # Use parsed DMARC
                    dmarc_result = checkers['dmarc'].check_parsed_dmarc(
                        entry['parsed_dmarc'],
                        record_id=record_id
                    )
                else:
                    # Query DNS
                    dmarc_result = checkers['dmarc'].check(domain)

                result['dmarc'] = dmarc_result.to_dict()
                print(f"  DMARC: {len(dmarc_result.issues)} issues, Policy: {dmarc_result.policy}")
            except Exception as e:
                result['dmarc'] = {'error': str(e)}
                print(f"  DMARC: Error - {e}")

        # Check DKIM (ALWAYS - brute force selector discovery, independent of email
        # indicators; skipped for organizational-parent DMARC-only entries)
        if 'dkim' in args.check_types and not parent_only:
            try:
                dkim_result = checkers['dkim'].check(domain)
                result['dkim'] = dkim_result.to_dict()
                print(f"  DKIM: {len(dkim_result.issues)} issues")
            except Exception as e:
                result['dkim'] = {'error': str(e)}
                print(f"  DKIM: Error - {e}")

        all_results.append(result)

    # ── Domain Availability Check ─────────────────────────────────────────────
    # Collect all SPF includes, extract their registered domains, and run a
    # single bulk check.  Issues are injected back into each result's SPF data
    # before output generation.
    # The same bulk call also covers the registrable domains of broken CNAME
    # targets found at DKIM/DMARC/SPF lookup names (one shared mechanism).
    cname_protocol_results = [
        result[key] for result in all_results for key in ('spf', 'dmarc', 'dkim')
        if isinstance(result.get(key), dict)
    ]
    cname_candidates = collect_cname_registration_candidates(cname_protocol_results)
    if cname_candidates and args.skip_domain_availability_check:
        print(f"\n[Domain Availability Check] Skipped - {len(cname_candidates)} CNAME target "
              f"domain(s) left as 'not_verified'")
    if ('spf' in args.check_types or cname_candidates) and not args.skip_domain_availability_check:
        if not _DOMAIN_CHECKER_AVAILABLE:
            msg = "\n[Domain Availability Check] Skipped - lib/domain/ packages not installed"
            if _DOMAIN_CHECKER_IMPORT_ERROR:
                msg += f"\n  Import error: {_DOMAIN_CHECKER_IMPORT_ERROR}"
            else:
                msg += " (hybridwhois, domain_availability_checker, etc.)"
            print(msg)
        else:
            # Build: registered_domain -> [(record_id, include_str)]
            domain_sources: dict[str, list] = {}
            if 'spf' in args.check_types:
                domain_sources = collect_spf_include_sources(
                    (result['record_id'], result.get('spf', {})) for result in all_results
                )

            bulk_availability: dict[str, dict] = {}
            if domain_sources or cname_candidates:
                print(f"\n[Domain Availability Check] Checking {len(domain_sources)} unique "
                      f"registered domain(s) from SPF includes and {len(cname_candidates)} "
                      f"from CNAME targets...")
                try:
                    bulk_availability = check_domains_availability(
                        sorted(set(domain_sources) | cname_candidates)
                    )
                except Exception as exc:
                    print(f"  Error: {exc}")

            if domain_sources:
                spf_by_record: dict[str, dict] = {}
                for result in all_results:
                    spf_by_record.setdefault(result['record_id'], result.get('spf', {}))
                added = apply_spf_include_availability(spf_by_record, domain_sources, bulk_availability)
                for event in added:
                    print(f"  [{event['record_id']}] include:{event['include']} -> "
                          f"{event['registered_domain']} {event['status']} ({event['severity']})")
                print(f"  Total - Unregistered (critical): "
                      f"{sum(e['severity'] == 'critical' for e in added)}, "
                      f"Potentially unregistered (high): "
                      f"{sum(e['severity'] == 'high' for e in added)}")

            if cname_candidates:
                added = apply_cname_registration_results(cname_protocol_results, bulk_availability)
                for event in added:
                    state = event['state'].replace('_', ' ')
                    print(f"  [{event['protocol']}] CNAME {', '.join(event['names'][:3])}"
                          f"{' ...' if len(event['names']) > 3 else ''} -> "
                          f"{event['registrable_domain']} {state} ({event['severity']})")
                print(f"  CNAME targets - issues added: {len(added)}")

    # Generate output files
    print("\n" + "=" * 80)
    print("[Generating Outputs]")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Determine base filenames
    if args.output:
        # User specified output filename
        base_name = args.output
        # Remove extension if provided
        if base_name.endswith('.json'):
            base_name = base_name[:-5]
        elif base_name.endswith('.xlsx'):
            base_name = base_name[:-5]

        json_base = f"{base_name}.json"
        excel_base = f"{base_name}.xlsx"
    else:
        # Default naming
        json_base = f"policy_check_{timestamp}.json"
        excel_base = f"policy_check_{timestamp}.xlsx"

    # Get unique filenames
    json_filename = get_unique_output_filename(args.output_dir, json_base)
    excel_filename = get_unique_output_filename(args.output_dir, excel_base)

    # JSON export
    json_path = os.path.join(args.output_dir, json_filename)
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    print(f"  JSON: {json_path}")

    # Excel export
    excel_path = os.path.join(args.output_dir, excel_filename)
    with pd.ExcelWriter(excel_path, engine='openpyxl') as writer:
        # Summary sheet
        summary_data = []
        for result in all_results:
            row = {
                'Record ID': result['record_id'],
                'Domain': result.get('domain', '')
            }

            if 'spf' in result:
                spf = result['spf']
                if 'error' in spf:
                    row['SPF Status'] = 'Error'
                    row['SPF Issues'] = spf['error']
                else:
                    row['SPF Status'] = 'OK' if len(spf.get('issues', [])) == 0 else 'Issues'
                    row['SPF Issues'] = len(spf.get('issues', []))
                    row['SPF Includes'] = len(spf.get('all_includes', []))
                    row['SPF IPs'] = len(spf.get('all_ip_addresses', []))

            if 'dmarc' in result:
                dmarc = result['dmarc']
                if 'error' in dmarc:
                    row['DMARC Status'] = 'Error'
                    row['DMARC Policy'] = dmarc['error']
                else:
                    row['DMARC Status'] = 'OK' if len(dmarc.get('issues', [])) == 0 else 'Issues'
                    row['DMARC Policy'] = dmarc.get('policy', 'N/A')
                    row['DMARC Issues'] = len(dmarc.get('issues', []))

            if 'dkim' in result:
                dkim = result['dkim']
                if 'error' in dkim:
                    row['DKIM Status'] = 'Error'
                else:
                    row['DKIM Status'] = 'OK' if len(dkim.get('issues', [])) == 0 else 'Issues'
                    row['DKIM Issues'] = len(dkim.get('issues', []))

            summary_data.append(row)

        df_summary = pd.DataFrame(summary_data)
        df_summary.to_excel(writer, sheet_name='Summary', index=False)

        # SPF Records sheet (full records)
        if 'spf' in args.check_types:
            spf_records_data = []
            for result in all_results:
                if 'spf' in result and 'error' not in result['spf']:
                    spf = result['spf']
                    spf_records_data.append({
                        'Record ID': result['record_id'],
                        'Domain': result.get('domain', ''),
                        'SPF Record': spf.get('spf_record', ''),
                        'ALL Qualifier': spf.get('all_qualifier', 'N/A'),
                        'Includes Count': len(spf.get('all_includes', [])),
                        'IP Addresses Count': len(spf.get('all_ip_addresses', [])),
                        'Issues Count': len(spf.get('issues', []))
                    })

            if spf_records_data:
                df_spf_records = pd.DataFrame(spf_records_data)
                df_spf_records.to_excel(writer, sheet_name='SPF Records', index=False)

        # DMARC Records sheet (full records)
        if 'dmarc' in args.check_types:
            dmarc_records_data = []
            for result in all_results:
                if 'dmarc' in result and 'error' not in result['dmarc']:
                    dmarc = result['dmarc']

                    # Only add row if a DMARC record was actually found
                    # Skip if no record (None or empty string)
                    if dmarc.get('dmarc_record'):
                        dmarc_records_data.append({
                            'Record ID': result['record_id'],
                            'Domain': result.get('domain', ''),
                            'DMARC Domain Checked': dmarc.get('dmarc_domain_checked', ''),
                            'DMARC Record': dmarc.get('dmarc_record', ''),
                            'Policy': dmarc.get('policy', 'N/A'),
                            'Subdomain Policy': dmarc.get('subdomain_policy', 'N/A'),
                            'Percentage': dmarc.get('percentage', 'N/A'),
                            'Issues Count': len(dmarc.get('issues', []))
                        })

            if dmarc_records_data:
                df_dmarc_records = pd.DataFrame(dmarc_records_data)
                df_dmarc_records.to_excel(writer, sheet_name='DMARC Records', index=False)

        # DKIM Records sheet (full records)
        if 'dkim' in args.check_types:
            dkim_records_data = []
            for result in all_results:
                if 'dkim' in result and 'error' not in result['dkim']:
                    dkim = result['dkim']
                    # DKIM can have multiple selectors
                    selectors_found = dkim.get('selectors_found', [])
                    if selectors_found:
                        for selector_info in selectors_found:
                            dkim_records_data.append({
                                'Record ID': result['record_id'],
                                'Domain': result.get('domain', ''),
                                'Selector': selector_info.get('selector', 'N/A'),
                                'DKIM Record': selector_info.get('dkim_record', ''),
                                'Key Type': selector_info.get('key_type', 'N/A'),
                                'Key Size': selector_info.get('key_size', 'N/A')
                            })

            if dkim_records_data:
                df_dkim_records = pd.DataFrame(dkim_records_data)
                df_dkim_records.to_excel(writer, sheet_name='DKIM Records', index=False)

        # SPF Issues sheet
        if 'spf' in args.check_types:
            spf_details = []
            for result in all_results:
                if 'spf' in result and 'error' not in result['spf']:
                    spf = result['spf']
                    for issue in spf.get('issues', []):
                        # Extract additional details from issue
                        additional_data = issue.get('additional_data', {})

                        # Format resolution path: join with " > "
                        resolution_path = issue.get('resolution_path', [])
                        resolution_path_str = ' > '.join(resolution_path) if resolution_path else ''

                        row = {
                            'Record ID': result['record_id'],
                            'Domain': result.get('domain', ''),
                            'Resolution Path': resolution_path_str,
                            'Severity': issue.get('severity', 'N/A'),
                            'Category': issue.get('category', 'N/A'),
                            'Title': issue.get('title', 'N/A')
                        }

                        # Add Service Name right after Title if available
                        service_name = additional_data.get('service_name', '')
                        if service_name:
                            row['Service Name'] = service_name

                        # Add Email Domain Indicators (from domain-level field, join list with ", ")
                        email_indicators = result.get('email_domain_indicators', [])
                        if email_indicators:
                            row['Email Domain Indicators'] = ', '.join(email_indicators)

                        # Add detailed columns based on issue type
                        if 'include' in additional_data:
                            row['Include'] = additional_data['include']
                            if 'registered_domain' in additional_data:
                                row['Domain To Buy'] = additional_data['registered_domain']
                        elif 'chain' in additional_data:
                            row['CNAME Chain'] = ' -> '.join(additional_data['chain'])
                            row['Domain To Buy'] = additional_data.get('registrable_domain', '')
                        elif 'ip_range' in additional_data:
                            row['IP Range'] = additional_data['ip_range']
                            # Add overlap details if present
                            if 'match_type' in additional_data:
                                row['Match Type'] = additional_data['match_type']
                            if 'dangerous_range' in additional_data:
                                row['Dangerous Range'] = additional_data['dangerous_range']
                            if 'overlap_start' in additional_data and additional_data['overlap_start']:
                                row['Overlap Start'] = additional_data['overlap_start']
                            if 'overlap_end' in additional_data and additional_data['overlap_end']:
                                row['Overlap End'] = additional_data['overlap_end']
                            if 'overlap_count' in additional_data and additional_data['overlap_count']:
                                row['Overlap Count'] = additional_data['overlap_count']
                        elif 'ip' in additional_data:
                            row['IP Address'] = additional_data['ip']
                            if 'as_organization' in additional_data:
                                row['AS Organization'] = additional_data['as_organization']

                        spf_details.append(row)

            if spf_details:
                df_spf = pd.DataFrame(spf_details)
                df_spf.to_excel(writer, sheet_name='SPF Issues', index=False)

        # DMARC Details sheet
        if 'dmarc' in args.check_types:
            dmarc_details = []
            for result in all_results:
                if 'dmarc' in result and 'error' not in result['dmarc']:
                    dmarc = result['dmarc']
                    for issue in dmarc.get('issues', []):
                        # Extract additional details from issue
                        additional_data = issue.get('additional_data', {})

                        row = {
                            'Record ID': result['record_id'],
                            'Domain': result.get('domain', ''),
                            'Severity': issue.get('severity', 'N/A'),
                            'Category': issue.get('category', 'N/A'),
                            'Title': issue.get('title', 'N/A')
                        }

                        # Add DMARC Domain Checked if different from queried domain
                        if 'dmarc_domain_checked' in dmarc:
                            row['DMARC Domain'] = dmarc['dmarc_domain_checked']

                        # Add Email Domain Indicators (from domain-level field, join list with ", ")
                        email_indicators = result.get('email_domain_indicators', [])
                        if email_indicators:
                            row['Email Domain Indicators'] = ', '.join(email_indicators)

                        # Add detailed columns based on issue type
                        if 'policy' in additional_data:
                            row['Policy'] = additional_data['policy']
                        if 'subdomain_policy' in additional_data:
                            row['Subdomain Policy'] = additional_data['subdomain_policy']
                        if 'percentage' in additional_data:
                            row['Percentage'] = additional_data['percentage']
                        if 'chain' in additional_data:
                            row['CNAME Chain'] = ' -> '.join(additional_data['chain'])
                            row['Domain To Buy'] = additional_data.get('registrable_domain', '')

                        dmarc_details.append(row)

            if dmarc_details:
                df_dmarc = pd.DataFrame(dmarc_details)
                df_dmarc.to_excel(writer, sheet_name='DMARC Issues', index=False)

        # DKIM Issues sheet
        if 'dkim' in args.check_types:
            dkim_details = []
            for result in all_results:
                if 'dkim' in result and 'error' not in result['dkim']:
                    dkim = result['dkim']
                    for issue in dkim.get('issues', []):
                        additional_data = issue.get('additional_data', {})
                        row = {
                            'Record ID': result['record_id'],
                            'Domain': result.get('domain', ''),
                            'Severity': issue.get('severity', 'N/A'),
                            'Category': issue.get('category', 'N/A'),
                            'Title': issue.get('title', 'N/A'),
                            'Selector': additional_data.get('selector')
                                        or ', '.join(additional_data.get('selectors', [])),
                            'Key Size': additional_data.get('key_size', ''),
                            'CNAME Chain': ' -> '.join(additional_data.get('chain', [])),
                            'Domain To Buy': additional_data.get('registrable_domain', ''),
                            'Detail': issue.get('detail', ''),
                        }
                        email_indicators = result.get('email_domain_indicators', [])
                        if email_indicators:
                            row['Email Domain Indicators'] = ', '.join(email_indicators)
                        dkim_details.append(row)

            if dkim_details:
                pd.DataFrame(dkim_details).to_excel(writer, sheet_name='DKIM Issues', index=False)

    print(f"  Excel: {excel_path}")

    print("\n" + "=" * 80)
    print(f"[Summary]")
    print(f"  Records processed: {len(all_results)}")
    print("=" * 80)

    # Auto-analyze unknown data if requested
    if args.auto_analyze_unknown and 'spf' in args.check_types:
        print("\n" + "=" * 80)
        print("[Auto-Analyzing Unknown SPF Data]")
        print("=" * 80)

        # Run unknown data analysis on the just-created JSON file
        check_unknown_spf_data(
            input_json_path=json_path,
            output_dir=args.output_dir,
            data_dir=args.data_dir,
            ptr_pool_size=args.ptr_pool_size,
            include_ptr_lookups=args.include_ptr,
            maxmind_license_key=os.environ.get('MAXMIND_LICENSE_KEY')
        )

    print("\nDone!")


def run_check_unknown_data_mode(args):
    """
    Run check_unknown_data mode: Analyze JSON output to find unknown SPF data.

    Args:
        args: Parsed command-line arguments
    """
    print("=" * 80)
    print("Mail AntiSpoof Policy Checker - Unknown Data Analysis Mode")
    print("=" * 80)

    if not args.spf_tree_json:
        print("\nError: --spf-tree-json is required for check_unknown_data mode")
        sys.exit(1)

    # Set MaxMind license key if available
    maxmind_license_key = os.environ.get('MAXMIND_LICENSE_KEY')

    # Determine output filenames
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if args.output:
        base_name = args.output
        if base_name.endswith('.json'):
            base_name = base_name[:-5]
        elif base_name.endswith('.xlsx'):
            base_name = base_name[:-5]
    else:
        base_name = f"unknown_spf_data_{timestamp}"

    # Note: check_unknown_spf_data generates its own filenames with timestamp
    # We'll need to modify it or handle output naming differently
    # For now, call the function directly
    check_unknown_spf_data(
        input_json_path=args.spf_tree_json,
        output_dir=args.output_dir,
        data_dir=args.data_dir,
        ptr_pool_size=args.ptr_pool_size,
        include_ptr_lookups=args.include_ptr,
        maxmind_license_key=maxmind_license_key
    )


def main():
    """Main entry point for CLI."""
    # Windows consoles/pipes default to cp1252: never crash on non-ASCII output text.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    parser = argparse.ArgumentParser(
        description='Mail AntiSpoof Policy Checker - Check SPF/DKIM/DMARC records and analyze unknown SPF data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check SPF/DMARC/DKIM for domains in a file
  python main.py --hostnames domains.txt

  # Check only SPF from a CSV file
  python main.py --records-csv domains.csv --check-types spf

  # Analyze unknown SPF data from JSON output
  python main.py --spf-tree-json output/spf_analysis.json --mode check_unknown_data --include-ptr

  # Use custom DNS server and output filename
  python main.py --hostnames domains.txt --nameservers 1.1.1.1 --output my_results

  # Custom DKIM selector list (replaces data/DKIM_Selectors.txt)
  python main.py --hostnames domains.txt --dkim-selector-file selector.txt
        """
    )

    # Input source (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '--hostnames',
        help='File with hostnames (one per line)'
    )
    input_group.add_argument(
        '--check-spf-records',
        help='CSV file with domain;SPF columns (only checks SPF, ignores --check-types)'
    )
    input_group.add_argument(
        '--spf-tree-json',
        help='JSON file or directory containing JSON files with parsed SPF trees (only checks SPF, ignores --check-types)'
    )
    input_group.add_argument(
        '--convert-json-report-to-excel',
        metavar='JSON_FILE',
        help='Convert a JSON report file to Excel format'
    )

    # Mode selection
    parser.add_argument(
        '--mode',
        choices=['check_record', 'check_unknown_data'],
        default='check_record',
        help='Mode of operation (default: check_record)'
    )

    # Record type selection (for check_record mode)
    parser.add_argument(
        '--check-types',
        nargs='+',
        choices=['spf', 'dkim', 'dmarc'],
        default=['spf', 'dkim', 'dmarc'],
        help='Record types to check (default: spf dkim dmarc)'
    )

    # Configuration options
    parser.add_argument(
        '--data-dir',
        default='./data',
        help='Directory containing CSV databases (default: ./data)'
    )
    parser.add_argument(
        '--nameservers',
        default=None,
        metavar='IP[,IP...]',
        help="Comma-separated custom DNS resolvers (e.g. '1.1.1.1,8.8.8.8'). Default: system default"
    )
    parser.add_argument(
        '--use-ns-record',
        action='store_true',
        help='Use domain\'s NS record for DNS queries'
    )
    parser.add_argument(
        '--dns-timeout',
        type=int,
        default=5,
        help='DNS query timeout in seconds (default: 5)'
    )
    parser.add_argument(
        '--max-dns-retries',
        type=int,
        default=3,
        help='Maximum DNS query retries per server before trying fallback DNS servers (default: 3)'
    )
    parser.add_argument(
        '--skip-email-domain-indicators-check',
        action='store_true',
        help='Skip email domain indicator checks and scan all domains (default: False)'
    )
    parser.add_argument(
        '--require-indicators',
        nargs='+',
        choices=['HAS_MX', 'HAS_SPF', 'HAS_DMARC', 'HAS_SMTP'],
        default=['HAS_MX'],
        help='Indicators required to consider domain as email domain (default: HAS_MX)'
    )
    parser.add_argument(
        '--email-checks',
        nargs='+',
        choices=['HAS_MX', 'HAS_SPF', 'HAS_DMARC', 'HAS_SMTP'],
        default=['HAS_MX', 'HAS_SPF', 'HAS_DMARC', 'HAS_SMTP'],
        help='Which email indicators to check (default: all). Use to skip expensive checks like HAS_SMTP'
    )
    parser.add_argument(
        '--disable-ptr-blacklist',
        action='store_true',
        help='Disable PTR blacklist from IPs via reverse DNS (enabled by default, only disables expensive IP lookups, not SPF tree extraction)'
    )
    parser.add_argument(
        '--disable-update-ptr-blacklist',
        action='store_true',
        help='Disable automatic update of PTR blacklist CSV on first run (use existing CSV only)'
    )
    parser.add_argument(
        '--ptr-blacklist-pool-size',
        type=int,
        default=20,
        help='Number of parallel PTR lookups when building PTR blacklist (default: 20)'
    )
    parser.add_argument(
        '--output-dir',
        default='./output',
        help='Output directory (default: ./output)'
    )
    parser.add_argument(
        '--output',
        help='Output filename (without extension, will create .json and .xlsx). If file exists, will prompt for new name.'
    )
    parser.add_argument(
        '--ptr-pool-size',
        type=int,
        default=20,
        help='Number of parallel PTR lookups for check_unknown_data mode (default: 20)'
    )
    parser.add_argument(
        '--include-ptr',
        action='store_true',
        help='Include PTR lookups in check_unknown_data mode'
    )
    parser.add_argument(
        '--auto-analyze-unknown',
        action='store_true',
        help='Automatically analyze unknown SPF data after check_record mode (only when SPF is checked)'
    )
    parser.add_argument(
        '--skip-domain-availability-check',
        action='store_true',
        help='Skip the unregistered/potentially-unregistered domain check on SPF includes '
             'and on broken CNAME targets (default: False)'
    )
    parser.add_argument(
        '--dkim-selector-file',
        metavar='FILE',
        default=None,
        help='Custom DKIM selector list (one selector per line, "#" comments allowed). '
             'Replaces the bundled list. Default: <data-dir>/DKIM_Selectors.txt'
    )
    parser.add_argument(
        '--skip-factordb-check',
        action='store_true',
        help='Do not look DKIM RSA moduli up on factordb.com (known factorizations). '
             'The offline key checks (exponent, small factor, prime modulus) still run (default: False)'
    )
    parser.add_argument(
        '--skip-cname-check',
        action='store_true',
        help='Skip the CNAME chain check on DKIM selector, _dmarc and SPF domain names (default: False)'
    )
    parser.add_argument(
        '--cname-max-depth',
        type=int,
        default=10,
        metavar='N',
        help='Maximum number of CNAME links followed before reporting excessive depth (default: 10)'
    )
    parser.add_argument(
        '--cname-wildcard-probes',
        type=int,
        default=3,
        metavar='N',
        help='Random sibling names probed per DKIM selector parent to detect wildcards '
             '(minimum and default: 3)'
    )
    parser.add_argument(
        '--async-mode',
        action='store_true',
        default=False,
        help='Process domains concurrently using asyncio (requires Python 3.9+). '
             'Default: disabled (sequential/sync mode)'
    )
    parser.add_argument(
        '--max-concurrent',
        type=int,
        default=50,
        metavar='N',
        help='Maximum number of domains processed concurrently when --async-mode is active. '
             '0 = unlimited. Default: 50'
    )
    parser.add_argument(
        '--max-global-concurrent',
        type=int,
        default=50,
        metavar='N',
        help='Maximum total concurrent DNS queries sent to checkdmarc across all nameservers '
             '(AsyncPooledDNSResolver global cap). Default: 50'
    )
    parser.add_argument(
        '--max-per-nameserver',
        type=int,
        default=20,
        metavar='N',
        help='Maximum concurrent DNS queries per individual nameserver '
             '(AsyncPooledDNSResolver per-NS cap). Default: 20'
    )

    args = parser.parse_args()

    # Normalize --nameservers (comma-separated string) into a list of IPs.
    if getattr(args, "nameservers", None):
        args.nameservers = [ns.strip() for ns in args.nameservers.split(",") if ns.strip()] or None

    # Handle JSON to Excel conversion (special case, doesn't use modes)
    if args.convert_json_report_to_excel:
        json_path = args.convert_json_report_to_excel
        if not os.path.exists(json_path):
            print(f"Error: JSON file not found: {json_path}")
            sys.exit(1)

        print("=" * 80)
        print("Mail AntiSpoof Policy Checker - JSON to Excel Conversion")
        print("=" * 80)
        print(f"\n[Input JSON]: {json_path}")

        try:
            excel_path = convert_json_report_to_excel(json_path)
            print(f"[Output Excel]: {excel_path}")
            print("\nDone!")
        except Exception as e:
            print(f"\nError converting JSON to Excel: {e}")
            sys.exit(1)
        return

    # Run appropriate mode
    if args.mode == 'check_record':
        run_check_record_mode(args)
    elif args.mode == 'check_unknown_data':
        run_check_unknown_data_mode(args)


if __name__ == '__main__':
    main()
