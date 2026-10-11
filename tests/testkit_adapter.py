"""Map native CLI JSON to the externally supplied Log Detective test-kit schema.

No answer-key reads, filtering of findings, or synthetic evidence. Structured
CLI error objects keep their empty finding list; callers must also inspect
status/error to distinguish rejected inputs from successful clean analyses.
"""
import json


def convert(stdout: str, log_path: str) -> dict:
    native = json.loads(stdout)
    findings = []
    for finding in native['findings']:
        evidence = finding['evidence']
        findings.append({'kind': 'observed', 'title': finding['title'],
                         'summary': finding['observation'], 'evidence': evidence})
        if finding['hypothesis']:
            findings.append({'kind': 'possible_cause', 'title': finding['title'] + ' — possible explanation',
                             'summary': finding['hypothesis'], 'evidence': evidence})
    return {'findings': findings}
