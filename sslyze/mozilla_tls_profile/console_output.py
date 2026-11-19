from typing import List

from sslyze.mozilla_tls_profile.tls_config_checker import (
    TlsConfigurationCheckResult,
    TlsConfigurationCheckStatusEnum,
    TlsConfigurationCriterionCheckResult,
)


_STATUS_TO_CONSOLE_LABEL = {
    TlsConfigurationCheckStatusEnum.COMPLIANT: "OK - Compliant.",
    TlsConfigurationCheckStatusEnum.NOT_COMPLIANT: "FAILED - Not compliant.",
    TlsConfigurationCheckStatusEnum.NOT_RUN: (
        "ERROR - Could not be evaluated; some required scan commands were not run."
    ),
    TlsConfigurationCheckStatusEnum.ERROR: (
        "ERROR - Could not be evaluated; some required scan commands returned an error."
    ),
}


def tls_configuration_check_result_as_console_output(
    server_display_string: str,
    check_result: TlsConfigurationCheckResult,
) -> List[str]:
    """Render a compliance check result as the lines printed to the console.

    Confirmed violations are always printed, even when the overall check is indeterminate. The criteria that could
    not be evaluated are listed separately so that an incomplete scan never looks like a successful compliance check.
    """
    output_lines = [f"    {server_display_string}: {_STATUS_TO_CONSOLE_LABEL[check_result.overall_status]}"]

    # The violations that could actually be confirmed
    for criterion_name, issue_description in check_result.issues.items():
        output_lines.append(f"        * {criterion_name}: {issue_description}")

    # The criteria that could not be evaluated, with the scan commands they depend on
    for criterion in check_result.indeterminate_criteria:
        output_lines.append(f"        * {criterion.criterion_name}: {_indeterminate_criterion_as_str(criterion)}")

    output_lines.append("")
    return output_lines


def _indeterminate_criterion_as_str(criterion: TlsConfigurationCriterionCheckResult) -> str:
    dependencies_as_str = ", ".join(
        f"{scan_command.value}={attempt_status.value}"
        for scan_command, attempt_status in criterion.dependencies.items()
    )
    if criterion.status == TlsConfigurationCheckStatusEnum.ERROR:
        return f"not evaluated because a required scan command returned an error ({dependencies_as_str})."
    return f"not evaluated because a required scan command was not run ({dependencies_as_str})."
