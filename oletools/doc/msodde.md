msodde
======

msodde detects and extracts DDE/DDEAUTO links from MS Office documents, RTF and
CSV. For Excel workbooks it can additionally build an evidence report that
separates a DDE *declaration* from a formula that actually *references* it.

## DDE declarations vs. references

A declaration is stored in an external-link part:

- OOXML (`.xlsx`, `.xlsm`): a `ddeLink` element in
  `xl/externalLinks/externalLinkN.xml`, with `ddeService` and `ddeTopic`.
- BIFF (`.xls`): a `SupBook` record whose virtual path contains the `0x03`
  separator between service and topic.
- XLSB (`.xlsb`): a `BrtBeginSupBook` record with type 1 (DDE), plus the
  service/topic strings.

A declaration does not prove that any worksheet uses it. msodde therefore
reports the declarations and the formula references separately, and assigns a
per-sheet evidence level:

| Level | Meaning |
| --- | --- |
| `none` | No DDE reference found on this sheet |
| `declaration-only` | A DDE declaration exists in the workbook, but no worksheet references it |
| `incomplete-analysis` | A worksheet or token stream could not be fully analyzed |
| `unresolved-reference` | A formula references a declaration or index that could not be resolved |
| `formula-reference` | A formula references an external declaration (non-DDE) |
| `confirmed-reference` | A formula index resolves to a DDE declaration |

Unknown formula tokens, truncated records, missing relationships and broken
`ExternSheet`/external-link indexes are always reported under
`coverage_limitations`. They are never collapsed into "no reference found",
because that would incorrectly suggest the workbook cannot trigger DDE.

Ordinary external-workbook or OLE links are reported with kind
`external-workbook` or `ole` and are not counted as DDE evidence.

## Usage

```text
msodde workbook.xlsx
msodde --excel-report-json workbook.xlsb
msodde --no-excel-report workbook.xlsx
```

The traditional `DDE Links:` output is unchanged. The Excel evidence report is
printed after it by default for Excel workbooks.

## Python API

```python
from oletools import msodde_excel

report = msodde_excel.analyze_workbook('workbook.xlsx')
print(report.document_evidence())   # e.g. "confirmed-reference"
for declaration in report.declarations:
    print(declaration.kind, declaration.service, declaration.topic)
for reference in report.references:
    print(reference.sheet, reference.cell, reference.evidence)
for limit in report.limitations:
    print(limit.location, limit.reason)
```

`report.as_dict()` returns the same information as JSON-compatible data. The
analysis is read-only: it does not evaluate formulas, start Excel, or contact
DDE targets.
