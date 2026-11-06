"""JSON formatters for checker results"""

import json
from typing import Dict, Any, List, Union
from ..models.spf_result import SPFResult
from ..models.dmarc_result import DMARCResult
from ..models.dkim_result import DKIMResult


class JSONFormatter:
    """Formats checker results as JSON"""

    @staticmethod
    def format_spf(result: SPFResult, pretty: bool = True) -> str:
        """
        Format SPF result as JSON.

        Args:
            result: SPFResult object
            pretty: Whether to pretty-print the JSON

        Returns:
            JSON string
        """
        data = result.to_dict()
        return json.dumps(data, indent=2 if pretty else None)

    @staticmethod
    def format_dmarc(result: DMARCResult, pretty: bool = True) -> str:
        """
        Format DMARC result as JSON.

        Args:
            result: DMARCResult object
            pretty: Whether to pretty-print the JSON

        Returns:
            JSON string
        """
        data = result.to_dict()
        return json.dumps(data, indent=2 if pretty else None)

    @staticmethod
    def format_dkim(result: DKIMResult, pretty: bool = True) -> str:
        """
        Format DKIM result as JSON.

        Args:
            result: DKIMResult object
            pretty: Whether to pretty-print the JSON

        Returns:
            JSON string
        """
        data = result.to_dict()
        return json.dumps(data, indent=2 if pretty else None)

    @staticmethod
    def format_combined(
        spf_result: SPFResult = None,
        dmarc_result: DMARCResult = None,
        dkim_result: DKIMResult = None,
        pretty: bool = True
    ) -> str:
        """
        Format combined results as JSON.
        All parameters are optional - include only the results you have.

        Args:
            spf_result: Optional SPFResult object
            dmarc_result: Optional DMARCResult object
            dkim_result: Optional DKIMResult object
            pretty: Whether to pretty-print the JSON

        Returns:
            JSON string
        """
        # At least one result must be provided
        if not any([spf_result, dmarc_result, dkim_result]):
            raise ValueError("At least one result (SPF, DMARC, or DKIM) must be provided")

        # Determine domain from available results
        domain = (
            spf_result.domain if spf_result else
            dmarc_result.domain if dmarc_result else
            dkim_result.domain
        )

        data = {'domain': domain}

        # Add SPF results if available
        if spf_result:
            data['spf'] = spf_result.to_dict()

        # Add DMARC results if available
        if dmarc_result:
            data['dmarc'] = dmarc_result.to_dict()

        # Add DKIM results if available
        if dkim_result:
            data['dkim'] = dkim_result.to_dict()

        # Calculate summary statistics
        total_issues = 0
        critical_issues = 0
        high_issues = 0
        summary = {}

        if spf_result:
            total_issues += len(spf_result.issues)
            critical_issues += sum(1 for i in spf_result.issues if i.severity.value == 'critical')
            high_issues += sum(1 for i in spf_result.issues if i.severity.value == 'high')
            summary['spf_issues'] = len(spf_result.issues)

        if dmarc_result:
            total_issues += len(dmarc_result.issues)
            critical_issues += sum(1 for i in dmarc_result.issues if i.severity.value == 'critical')
            high_issues += sum(1 for i in dmarc_result.issues if i.severity.value == 'high')
            summary['dmarc_issues'] = len(dmarc_result.issues)

        if dkim_result:
            total_issues += len(dkim_result.issues)
            critical_issues += sum(1 for i in dkim_result.issues if i.severity.value == 'critical')
            high_issues += sum(1 for i in dkim_result.issues if i.severity.value == 'high')
            summary['dkim_issues'] = len(dkim_result.issues)

        summary['total_issues'] = total_issues
        summary['critical_issues'] = critical_issues
        summary['high_issues'] = high_issues

        data['summary'] = summary

        return json.dumps(data, indent=2 if pretty else None)

    @staticmethod
    def save_to_file(json_str: str, file_path: str):
        """
        Save JSON string to file.

        Args:
            json_str: JSON string
            file_path: Path to output file
        """
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(json_str)

    @staticmethod
    def format_issues_only(
        results: Union[SPFResult, DMARCResult, DKIMResult, List],
        pretty: bool = True
    ) -> str:
        """
        Format only the issues from result(s) as JSON.

        Args:
            results: Single result or list of results
            pretty: Whether to pretty-print the JSON

        Returns:
            JSON string with issues only
        """
        if not isinstance(results, list):
            results = [results]

        all_issues = []
        for result in results:
            for issue in result.issues:
                issue_dict = issue.to_dict()
                issue_dict['domain'] = result.domain
                all_issues.append(issue_dict)

        return json.dumps(all_issues, indent=2 if pretty else None)
