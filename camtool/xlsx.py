"""Minimal standard-library .xlsx writer: inline strings, numbers, bold frozen header, autofilter.

Strings are always written as text (never as formulas), so evidence values starting with '='
cannot execute in Excel.
"""
from __future__ import annotations

import re
import zipfile
from xml.sax.saxutils import escape

_CTRL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿\ud800-\udfff]")   # chars XML 1.0 forbids
_BAD_NAME = re.compile(r"[\[\]:*?/\\]")


def _col(n: int) -> str:
    s = ""
    n += 1
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def _cell(ref: str, v, style: int = 0) -> str:
    st = f' s="{style}"' if style else ""
    if isinstance(v, bool):
        v = str(v)
    if isinstance(v, (int, float)) and v == v and abs(v) < 1e15:
        return f'<c r="{ref}"{st}><v>{v}</v></c>'
    text = _CTRL.sub("", "" if v is None else str(v))[:32767]
    return f'<c r="{ref}" t="inlineStr"{st}><is><t xml:space="preserve">{escape(text)}</t></is></c>'


def _sheet(header: list, rows: list) -> str:
    widths = [min(60, max(10, len(str(h)) + 2)) for h in header]
    for r in rows[:500]:
        for i, v in enumerate(r[:len(widths)]):
            widths[i] = min(60, max(widths[i], len(str(v)) + 2))
    out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
           '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
           '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" '
           'state="frozen"/></sheetView></sheetViews><cols>']
    out += [f'<col min="{i + 1}" max="{i + 1}" width="{w}" customWidth="1"/>' for i, w in enumerate(widths)]
    out.append("</cols><sheetData>")
    out.append('<row r="1">' + "".join(_cell(f"{_col(i)}1", h, 1) for i, h in enumerate(header)) + "</row>")
    for n, r in enumerate(rows, start=2):
        out.append(f'<row r="{n}">' + "".join(_cell(f"{_col(i)}{n}", v) for i, v in enumerate(r)) + "</row>")
    last = f"{_col(max(len(header) - 1, 0))}{max(len(rows) + 1, 1)}"
    out.append(f'</sheetData><autoFilter ref="A1:{last}"/></worksheet>')
    return "".join(out)


def write_xlsx(path: str, sheets: list[tuple[str, list[str], list[list]]]) -> None:
    names, used = [], set()
    for name, _, _ in sheets:
        n = _BAD_NAME.sub("_", name)[:31] or "Sheet"
        base, i = n, 2
        while n.lower() in used:
            n = f"{base[:28]}_{i}"
            i += 1
        used.add(n.lower())
        names.append(n)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        _w = z.writestr

        def writestr(name, data):                 # fixed timestamp -> byte-identical output
            zi = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            _w(zi, data)
        z.writestr = writestr
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                   '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                   '<Default Extension="xml" ContentType="application/xml"/>'
                   '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                   '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
                   + "".join(f'<Override PartName="/xl/worksheets/sheet{i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                             for i in range(len(sheets))) + "</Types>")
        z.writestr("_rels/.rels",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
                   '</Relationships>')
        z.writestr("xl/workbook.xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                   'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
                   + "".join(f'<sheet name="{escape(n, {chr(34): "&quot;"})}" sheetId="{i + 1}" r:id="rId{i + 1}"/>'
                             for i, n in enumerate(names)) + "</sheets></workbook>")
        z.writestr("xl/_rels/workbook.xml.rels",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   + "".join(f'<Relationship Id="rId{i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i + 1}.xml"/>'
                             for i in range(len(sheets)))
                   + f'<Relationship Id="rId{len(sheets) + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
                   '</Relationships>')
        z.writestr("xl/styles.xml",
                   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                   '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                   '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
                   '<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font></fonts>'
                   '<fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill>'
                   '<fill><patternFill patternType="solid"><fgColor rgb="FF2F5D8A"/></patternFill></fill></fills>'
                   '<borders count="1"><border/></borders><cellStyleXfs count="1"><xf/></cellStyleXfs>'
                   '<cellXfs count="2"><xf/><xf fontId="1" fillId="2" applyFont="1" applyFill="1"/></cellXfs>'
                   '</styleSheet>')
        for i, (_, header, rows) in enumerate(sheets):
            z.writestr(f"xl/worksheets/sheet{i + 1}.xml", _sheet(header, rows))
