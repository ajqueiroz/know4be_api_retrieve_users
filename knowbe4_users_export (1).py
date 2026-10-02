#!/usr/bin/env python3
"""
KnowBe4 user report
===================
Gets the list of users from KnowBe4 (Europe), leaves out the email addresses
listed in exceptions.txt, and saves the result as CSV and/or PDF in the
"Reports" folder next to this file.

Normal use: open this folder in Visual Studio Code, open this file and press
the Run button (the triangle, top right). See "How to run.txt".

Everything a day-to-day user needs is in two plain text files:
    exceptions.txt   one email address per line - users to leave out
    settings.ini     csv / pdf / both, and a couple of other choices

For IT - optional command-line overrides:
    python knowbe4_users_export.py --format pdf --users all
    python knowbe4_users_export.py -x someone@example.com --exceptions flag
    python knowbe4_users_export.py --group-id 1234 --columns email,first_name,last_name
    python knowbe4_users_export.py --forget-key        # remove the saved API key

API key: read from the KNOWBE4_API_KEY environment variable if set, otherwise
from the operating system's credential store (Windows Credential Manager),
otherwise asked for once and then saved there. It is never written to a file
and never accepted on the command line.
"""
from __future__ import annotations

import argparse
import configparser
import csv
import getpass
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

# --------------------------------------------------------------------------- #
# Fixed configuration
# --------------------------------------------------------------------------- #
# Europe. This matches a console address of eu.knowbe4.com.
# (If your console is at de.knowbe4.com or uk.knowbe4.com, change "eu" to "de" or "uk".)
BASE_URL = "https://eu.api.knowbe4.com"

HERE = Path(__file__).resolve().parent
SETTINGS_FILE = HERE / "settings.ini"
EXCEPTIONS_FILE = HERE / "exceptions.txt"
REPORTS_DIR = HERE / "Reports"

KEYRING_SERVICE = "KnowBe4 Reporting API"
KEYRING_USER = "api-key"

PER_PAGE = 500                # the most KnowBe4 returns per request
MIN_REQUEST_INTERVAL = 1.25   # seconds; keeps us under KnowBe4's 50 requests/minute limit
TIMEOUT = 60
MAX_RETRIES = 5

DEFAULT_SETTINGS = {"format": "both", "users": "active", "exceptions": "remove"}
ALLOWED_SETTINGS = {
    "format": ("csv", "pdf", "both"),
    "users": ("active", "archived", "all"),
    "exceptions": ("remove", "flag"),
}

CSV_DEFAULT_COLUMNS = [
    "id", "email", "first_name", "last_name", "job_title", "department",
    "division", "location", "manager_name", "manager_email", "status",
    "phish_prone_percentage", "current_risk_score", "joined_on",
    "last_sign_in", "employee_number", "groups",
]
PDF_DEFAULT_COLUMNS = [
    "email", "first_name", "last_name", "job_title", "department",
    "manager_name", "status", "phish_prone_percentage", "current_risk_score",
    "last_sign_in",
]
LABELS = {
    "id": "ID",
    "email": "Email",
    "phish_prone_percentage": "Phish-prone %",
    "current_risk_score": "Risk score",
    "manager_name": "Manager",
    "last_sign_in": "Last sign-in",
    "joined_on": "Joined",
    "employee_number": "Employee no.",
    "exception": "Exception",
}


class ApiError(Exception):
    """Something went wrong talking to KnowBe4 (message is safe to show the user)."""


class KeyRejected(ApiError):
    """KnowBe4 did not accept the API key."""


def say(msg: str = "") -> None:
    print(msg, flush=True)


try:
    import requests
except ImportError:
    say("A required component ('requests') is not installed on this computer.")
    say("In the Terminal panel, type this and press Enter, then run the report again:")
    say("    py -m pip install -r requirements.txt")
    sys.exit(1)


# --------------------------------------------------------------------------- #
# Settings and API key
# --------------------------------------------------------------------------- #
def load_settings() -> dict:
    """Read settings.ini; anything missing or misspelt falls back to the default."""
    settings = dict(DEFAULT_SETTINGS)
    if not SETTINGS_FILE.is_file():
        return settings
    parser = configparser.ConfigParser(inline_comment_prefixes=(";", "#"))
    try:
        parser.read(SETTINGS_FILE, encoding="utf-8-sig")
    except configparser.Error as exc:
        say(f"Note: settings.ini could not be read ({exc.__class__.__name__}); using the standard settings.")
        return settings
    if not parser.has_section("report"):
        return settings
    for name, allowed in ALLOWED_SETTINGS.items():
        value = parser.get("report", name, fallback="").strip().lower()
        if not value:
            continue
        if value in allowed:
            settings[name] = value
        else:
            say(f"Note: in settings.ini, '{name} = {value}' is not one of {', '.join(allowed)}. "
                f"Using '{settings[name]}'.")
    return settings


def _keyring():
    """The operating system's credential store, or None if it is not available."""
    try:
        import keyring
        keyring.get_password(KEYRING_SERVICE, KEYRING_USER)   # check there is a working store
        return keyring
    except Exception:
        return None


def get_api_key() -> tuple[str, str]:
    """Return (key, where it came from: 'env' | 'saved' | 'typed')."""
    env = os.environ.get("KNOWBE4_API_KEY", "").strip()
    if env:
        return env, "env"

    store = _keyring()
    if store:
        saved = store.get_password(KEYRING_SERVICE, KEYRING_USER)
        if saved:
            return saved, "saved"

    say("First-time setup: this computer needs the KnowBe4 API key.")
    say("  Where to find it: KnowBe4 console > Account Settings > Account Integrations > API")
    say("                    > Reporting API (your KnowBe4 administrator can provide it).")
    say("  Paste it below and press Enter. Nothing will appear on screen as you paste -")
    say("  that is normal, it keeps the key hidden.")
    say()
    key = getpass.getpass("  API key: ").strip()
    if not key:
        raise ApiError("No API key was entered.")
    return key, "typed"


def save_api_key(key: str) -> bool:
    store = _keyring()
    if not store:
        return False
    try:
        store.set_password(KEYRING_SERVICE, KEYRING_USER, key)
        return True
    except Exception:
        return False


def forget_api_key() -> bool:
    store = _keyring()
    if not store:
        return False
    try:
        store.delete_password(KEYRING_SERVICE, KEYRING_USER)
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# KnowBe4 API
# --------------------------------------------------------------------------- #
_last_request = 0.0


def api_get(session: requests.Session, url: str, params: dict) -> requests.Response:
    """GET with request spacing, and retry/backoff on 429 and 5xx."""
    global _last_request
    for attempt in range(1, MAX_RETRIES + 1):
        wait = MIN_REQUEST_INTERVAL - (time.monotonic() - _last_request)
        if wait > 0:
            time.sleep(wait)
        _last_request = time.monotonic()

        try:
            resp = session.get(url, params=params, timeout=TIMEOUT)
        except requests.exceptions.SSLError as exc:
            raise ApiError(
                "A secure connection to KnowBe4 could not be set up. This is usually the company "
                "network's web filter - please ask IT. (Technical detail: SSL certificate error.)"
            ) from exc
        except requests.RequestException as exc:
            if attempt == MAX_RETRIES:
                raise ApiError(
                    "KnowBe4 could not be reached. Check that this computer is connected to the "
                    "internet (and the VPN, if you use one), then try again."
                ) from exc
            delay = 2 ** attempt
            say(f"  Connection problem; trying again in {delay} seconds...")
            time.sleep(delay)
            continue

        if resp.status_code == 429 or resp.status_code >= 500:
            if attempt == MAX_RETRIES:
                raise ApiError(f"KnowBe4 kept returning an error (code {resp.status_code}). Please try again later.")
            retry_after = resp.headers.get("Retry-After", "")
            # A tripped rate limit locks the key out for about five minutes.
            delay = int(retry_after) if retry_after.isdigit() else (300 if resp.status_code == 429 else 2 ** attempt * 5)
            if resp.status_code == 429:
                say(f"  KnowBe4 asked us to slow down. Waiting {max(delay // 60, 1) if delay >= 60 else delay} "
                    f"{'minute(s)' if delay >= 60 else 'second(s)'} - please leave this window open...")
            else:
                say(f"  KnowBe4 is busy (code {resp.status_code}); trying again in {delay} seconds...")
            time.sleep(delay)
            continue

        if resp.status_code == 401:
            raise KeyRejected("KnowBe4 did not accept the API key.")
        if resp.status_code == 403:
            raise ApiError("KnowBe4 refused the request. Reporting API access may be switched off for the "
                           "account - please ask your KnowBe4 administrator.")
        if not resp.ok:
            raise ApiError(f"KnowBe4 returned an unexpected error (code {resp.status_code}): {resp.text[:200]}")
        return resp

    raise ApiError("The request to KnowBe4 failed.")  # not reached


def _items(body) -> list:
    """The API returns either a bare list or an envelope with a 'data' list."""
    if isinstance(body, list):
        return body
    if isinstance(body, dict) and isinstance(body.get("data"), list):
        return body["data"]
    raise ApiError(f"KnowBe4 sent a reply this tool does not understand: {str(body)[:200]}")


def _next_cursor(resp: requests.Response, body) -> str | None:
    """Find the next-page cursor in the response headers or body."""
    for header in ("X-Next-Cursor", "Next-Cursor", "X-Cursor"):
        value = resp.headers.get(header)
        if value and value.lower() not in ("true", "null"):
            return value

    link = resp.headers.get("Link", "")
    match = re.search(r'<[^>]*[?&]cursor=([^&>]+)[^>]*>;\s*rel="?next"?', link)
    if match:
        return requests.utils.unquote(match.group(1))

    if isinstance(body, dict):
        for path in (("next_cursor",), ("meta", "next_cursor"), ("pagination", "next_cursor"),
                     ("nextCursor",), ("meta", "nextCursor"), ("pagination", "nextCursor")):
            value = body
            for key in path:
                value = value.get(key) if isinstance(value, dict) else None
            if value not in (None, "", False):
                return str(value)
    return None


def fetch_users(session: requests.Session, status: str, group_id: int | None) -> tuple[list[dict], bool]:
    """
    Retrieve every user. Returns (users, complete).

    Uses cursor paging; if KnowBe4 gives no cursor to follow on a full first
    page, it re-checks with page numbers. 'complete' is False only if neither
    method could get past a full page, i.e. the list may be cut short.
    """
    url = f"{BASE_URL}/v1/users"
    base = {"per_page": PER_PAGE}
    if status != "all":
        base["status"] = status
    if group_id:
        base["group_id"] = group_id

    users: dict = {}     # keyed by user id, so a repeated page can never duplicate rows

    def add(page_items) -> int:
        before = len(users)
        for user in page_items:
            users.setdefault(user.get("id", id(user)), user)
        return len(users) - before

    cursor, seen, request_no, use_page_numbers = "true", set(), 0, False
    while True:
        request_no += 1
        resp = api_get(session, url, {**base, "cursor": cursor})
        body = resp.json()
        page_items = _items(body)
        added = add(page_items)
        say(f"  {len(users)} users received...")

        nxt = _next_cursor(resp, body)
        if not page_items or not nxt:
            use_page_numbers = request_no == 1 and len(page_items) >= PER_PAGE
            break
        if nxt in seen or added == 0:
            return list(users.values()), False
        seen.add(nxt)
        cursor = nxt

    if use_page_numbers:
        users.clear()
        page = 1
        while True:
            page_items = _items(api_get(session, url, {**base, "page": page}).json())
            added = add(page_items)
            say(f"  {len(users)} users received...")
            if len(page_items) < PER_PAGE:
                break
            if added == 0:
                return list(users.values()), False
            page += 1

    return list(users.values()), True


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #
def load_exceptions(inline: list[str], files: list[Path]) -> set[str]:
    """Collect exception emails from exceptions.txt and/or -x values."""
    raw: list[str] = []
    for value in inline or []:
        raw.extend(value.split(","))
    for path in files:
        try:
            text = path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            text = path.read_text(encoding="cp1252", errors="replace")
        for line in text.splitlines():
            line = line.split("#", 1)[0]
            raw.extend(re.split(r"[,;\s]+", line))

    emails = set()
    for item in raw:
        item = item.strip().strip("\"'<>").lower()
        if not item:
            continue
        if "@" not in item:
            if item != "email":  # tolerate a header row
                say(f"Note: '{item}' in the exception list is not an email address, so it was ignored.")
            continue
        emails.add(item)
    return emails


def user_emails(user: dict) -> set[str]:
    """Primary email plus any aliases, lower-cased."""
    found = {str(user.get("email") or "").strip().lower()}
    for alias in user.get("aliases") or []:
        found.add(str(alias).strip().lower())
    found.discard("")
    return found


def apply_exceptions(users: list[dict], exceptions: set[str], mode: str):
    """Return (rows_for_report, matched_users, exception_emails_not_found)."""
    matched, kept, hit = [], [], set()
    for user in users:
        overlap = user_emails(user) & exceptions
        if overlap:
            hit |= overlap
            matched.append(user)
            if mode == "flag":
                kept.append({**user, "exception": "Yes"})
        else:
            kept.append({**user, "exception": "No"} if mode == "flag" else user)
    return kept, matched, sorted(exceptions - hit)


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (list, tuple)):
        return "; ".join(cell(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def pdf_cell(value) -> str:
    """Like cell(), but shortens timestamps (2026-09-30T08:15:00.000Z -> 2026-09-30 08:15)."""
    text = cell(value)
    match = re.fullmatch(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}).*", text)
    return f"{match.group(1)} {match.group(2)}" if match else text


def csv_safe(text: str) -> str:
    """Stop spreadsheet apps treating text from KnowBe4 as a formula."""
    if not text:
        return text
    if text[0] in "=@\t\r":
        return "'" + text
    if text[0] in "+-" and not re.fullmatch(r"[+\-]?[\d\s().\-]+", text):  # leave phone numbers / numbers alone
        return "'" + text
    return text


def label(column: str) -> str:
    return LABELS.get(column, column.replace("_", " ").capitalize())


def write_csv(path: Path, rows: list[dict], columns: list[str]) -> None:
    # utf-8-sig so Excel shows accented names correctly
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh)
        writer.writerow(columns)
        for row in rows:
            writer.writerow([csv_safe(cell(row.get(col))) for col in columns])


def _pdf_fonts() -> tuple[str, str]:
    """Use a font that covers all European alphabets (the built-in PDF font does not)."""
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    windows_fonts = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts"
    candidates = [
        (windows_fonts / "arial.ttf", windows_fonts / "arialbd.ttf"),
        (Path("/System/Library/Fonts/Supplemental/Arial.ttf"), Path("/System/Library/Fonts/Supplemental/Arial Bold.ttf")),
        (Path("/Library/Fonts/Arial.ttf"), Path("/Library/Fonts/Arial Bold.ttf")),
        (Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"), Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")),
    ]
    for regular, bold in candidates:
        if regular.is_file() and bold.is_file():
            try:
                pdfmetrics.registerFont(TTFont("Report", str(regular)))
                pdfmetrics.registerFont(TTFont("Report-Bold", str(bold)))
                return "Report", "Report-Bold"
            except Exception:
                continue
    return "Helvetica", "Helvetica-Bold"


def write_pdf(path: Path, rows: list[dict], columns: list[str], meta: dict) -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import LongTable, Paragraph, SimpleDocTemplate, Spacer, TableStyle
    except ImportError as exc:
        raise ApiError("The PDF component ('reportlab') is not installed. In the Terminal panel, type\n"
                       "    py -m pip install -r requirements.txt\n"
                       "and press Enter, then run the report again.") from exc

    regular, bold = _pdf_fonts()
    grey = colors.HexColor("#444444")
    navy = colors.HexColor("#12233D")
    title = ParagraphStyle("title", fontName=bold, fontSize=18, leading=22, alignment=1, spaceAfter=8)
    small = ParagraphStyle("small", fontName=regular, fontSize=8, leading=11, textColor=grey)
    small_bold = ParagraphStyle("small_bold", parent=small, fontName=bold)
    warn = ParagraphStyle("warn", parent=small_bold, textColor=colors.HexColor("#B00020"))
    body = ParagraphStyle("cell", fontName=regular, fontSize=7, leading=8.5, wordWrap="CJK")
    head = ParagraphStyle("head", fontName=bold, fontSize=7, leading=8.5, textColor=colors.white)

    page = landscape(A4)
    margin = 12 * mm
    doc = SimpleDocTemplate(str(path), pagesize=page, leftMargin=margin, rightMargin=margin,
                            topMargin=margin, bottomMargin=14 * mm,
                            title="KnowBe4 User Report", author="KnowBe4 user report tool")

    story = [Paragraph("KnowBe4 User Report", title)]
    sep = " &nbsp;|&nbsp; "
    line1 = [f"Generated: {meta['generated']}", "Region: Europe", f"Users included: {meta['status']}"]
    if meta["group_id"]:
        line1.append(f"Group ID: {meta['group_id']}")
    line2 = [f"Users in KnowBe4: {meta['retrieved']}",
             f"Exceptions {'flagged' if meta['mode'] == 'flag' else 'left out'}: {meta['matched']}",
             f"Users in this report: {len(rows)}"]
    story += [Paragraph(sep.join(line1), small), Paragraph(sep.join(line2), small)]
    if not meta["complete"]:
        story.append(Paragraph("WARNING: KnowBe4 may hold more users than this report shows. "
                               "Treat this list as incomplete.", warn))
    story.append(Spacer(1, 5 * mm))

    # Column widths in proportion to content length, within sensible bounds.
    sample = rows[:500]
    weights = []
    for col in columns:
        longest = max([len(pdf_cell(r.get(col))) for r in sample] or [0])
        # never narrower than the longest word in the heading, so headings don't break mid-word
        floor = max(len(word) for word in label(col).split()) + 3
        weights.append(max(min(longest, 30), floor, 7))
    usable = page[0] - 2 * margin
    widths = [usable * w / sum(weights) for w in weights]

    data = [[Paragraph(escape(label(c)), head) for c in columns]]
    for row in rows:
        data.append([Paragraph(escape(pdf_cell(row.get(c))), body) for c in columns])

    style = [
        ("BACKGROUND", (0, 0), (-1, 0), navy),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#C9CED6")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F3F5F8")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]
    if meta["mode"] == "flag":
        for i, row in enumerate(rows, start=1):
            if row.get("exception") == "Yes":
                style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#FFF2CC")))

    if rows:
        table = LongTable(data, colWidths=widths, repeatRows=1)
        table.setStyle(TableStyle(style))
        story.append(table)
    else:
        story.append(Paragraph("No users to show.", small))

    if meta["mode"] == "remove" and meta["matched_emails"]:
        story.append(Spacer(1, 6 * mm))
        story.append(Paragraph("Exceptions applied (left out of this report)", small_bold))
        story.append(Paragraph(escape(", ".join(meta["matched_emails"])), small))

    def footer(canvas, _doc):
        canvas.saveState()
        canvas.setFont(regular, 7)
        canvas.setFillColor(colors.HexColor("#666666"))
        canvas.drawString(margin, 8 * mm, f"KnowBe4 User Report - {meta['generated']} - Confidential")
        canvas.drawRightString(page[0] - margin, 8 * mm, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def parse_args(argv, settings: dict) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="KnowBe4 (Europe) user report: CSV/PDF with an email exception list. "
                    "With no options it uses settings.ini and exceptions.txt next to this file.")
    p.add_argument("--format", "-f", choices=ALLOWED_SETTINGS["format"], default=settings["format"],
                   help="Output format (default: from settings.ini)")
    p.add_argument("--users", choices=ALLOWED_SETTINGS["users"], default=settings["users"],
                   help="Which users to include (default: from settings.ini)")
    p.add_argument("--exceptions", choices=ALLOWED_SETTINGS["exceptions"], default=settings["exceptions"],
                   help="remove = leave exception users out; flag = keep them and mark them")
    p.add_argument("--exclude", "-x", action="append", metavar="EMAIL", default=[],
                   help="Extra exception email, in addition to exceptions.txt. Can be repeated.")
    p.add_argument("--exclude-file", metavar="FILE", help="Use this file instead of exceptions.txt")
    p.add_argument("--group-id", type=int, help="Only users in this KnowBe4 group ID")
    p.add_argument("--columns", metavar="A,B,C", help="Comma-separated KnowBe4 field names to include, in order")
    p.add_argument("--forget-key", action="store_true", help="Remove the saved API key and exit")
    p.add_argument("--no-open", action="store_true", help="Do not open the Reports folder when finished")
    return p.parse_args(argv)


def run(argv=None) -> int:
    say("KnowBe4 user report")
    say("-------------------")
    args = parse_args(argv, load_settings())

    if args.forget_key:
        say("The saved API key was removed." if forget_api_key() else "There was no saved API key to remove.")
        return 0

    # Exceptions
    if args.exclude_file:
        exception_file = Path(args.exclude_file)
        if not exception_file.is_file():
            raise ApiError(f"The exception file was not found: {exception_file}")
        files = [exception_file]
    else:
        files = [EXCEPTIONS_FILE] if EXCEPTIONS_FILE.is_file() else []
    exceptions = load_exceptions(args.exclude, files)

    # Get the users
    api_key, key_source = get_api_key()
    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {api_key}", "Accept": "application/json"})
    say("Connecting to KnowBe4 (Europe)...")
    try:
        users, complete = fetch_users(session, args.users, args.group_id)
    except KeyRejected:
        if key_source == "saved":
            forget_api_key()
            raise ApiError("KnowBe4 did not accept the saved API key - it has probably been replaced.\n"
                           "The old key has been removed from this computer. Run the report again and "
                           "paste the new key when asked.")
        if key_source == "env":
            raise ApiError("KnowBe4 did not accept the API key in the KNOWBE4_API_KEY environment variable.")
        raise ApiError("KnowBe4 did not accept that API key. Check that all of it was copied, then run the "
                       "report again.")

    if key_source == "typed":
        if save_api_key(api_key):
            say("  The API key worked and has been saved securely on this computer; you will not be asked again.")
        else:
            say("  The API key worked. It could not be saved on this computer, so you will be asked for it each time.")

    # Build the report
    rows, matched, not_found = apply_exceptions(users, exceptions, args.exceptions)
    rows.sort(key=lambda r: cell(r.get("email")).lower())

    custom = [c.strip() for c in args.columns.split(",") if c.strip()] if args.columns else None
    extra = ["exception"] if args.exceptions == "flag" else []
    now = datetime.now()
    stem = f"KnowBe4_Users_{now:%Y-%m-%d_%H%M%S}"

    written = []
    try:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        if args.format in ("csv", "both"):
            path = REPORTS_DIR / f"{stem}.csv"
            write_csv(path, rows, (custom or CSV_DEFAULT_COLUMNS) + extra)
            written.append(path)
        if args.format in ("pdf", "both"):
            path = REPORTS_DIR / f"{stem}.pdf"
            write_pdf(path, rows, (custom or PDF_DEFAULT_COLUMNS) + extra, {
                "generated": now.strftime("%Y-%m-%d %H:%M"),
                "status": args.users, "group_id": args.group_id, "complete": complete,
                "retrieved": len(users), "matched": len(matched), "mode": args.exceptions,
                "matched_emails": sorted(str(u.get("email", "")).lower() for u in matched),
            })
            written.append(path)
    except OSError as exc:
        raise ApiError(f"The report could not be saved in {REPORTS_DIR}\n({exc.strerror or exc}). "
                       "Check that the folder is not read-only and that you have space on the drive.") from exc

    # Summary
    say()
    say("Finished.")
    say(f"  Users in KnowBe4 ({args.users}):".ljust(34) + str(len(users)))
    say(f"  Exceptions {'flagged' if args.exceptions == 'flag' else 'left out'}:".ljust(34) + str(len(matched)))
    say("  Users in the report:".ljust(34) + str(len(rows)))
    if not_found:
        say()
        say("  These exception emails were NOT found in KnowBe4 - please check the spelling:")
        for email in not_found:
            say(f"    {email}")
    if not complete:
        say()
        say("  WARNING: KnowBe4 may hold more users than were received, so this report may be")
        say("  incomplete. Compare the number above with the user count in the KnowBe4 console")
        say("  and tell IT if they differ.")
    say()
    say(f"  Saved in: {REPORTS_DIR}")
    for path in written:
        say(f"    {path.name}")
    if sys.platform == "win32" and not args.no_open:
        try:
            os.startfile(REPORTS_DIR)   # show the Reports folder in File Explorer
        except OSError:
            pass
    return 0


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass
    try:
        return run(argv)
    except ApiError as exc:
        say()
        say(f"PROBLEM: {exc}")
        return 1
    except KeyboardInterrupt:
        say()
        say("Stopped.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
