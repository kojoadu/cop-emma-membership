"""Encrypt and atomically import membership.xlsx using an authenticated account."""

from __future__ import annotations

import argparse
import getpass
import sys
import tomllib
from pathlib import Path
from uuid import uuid4

from supabase import create_client

from membership import (
    decode_encryption_key,
    encrypt_record,
    encrypt_record_fields,
    workbook_records,
)


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Import the local membership workbook into an empty encrypted dataset."
    )
    parser.add_argument(
        "workbook",
        nargs="?",
        type=Path,
        default=project_root / "membership.xlsx",
        help="Path to the local Excel workbook (default: project-root membership.xlsx)",
    )
    args = parser.parse_args()

    secrets_path = project_root / ".streamlit" / "secrets.toml"
    if not secrets_path.is_file():
        print(
            "Missing .streamlit/secrets.toml. Configure Supabase and encryption secrets first.",
            file=sys.stderr,
        )
        return 2
    with secrets_path.open("rb") as secrets_file:
        settings = tomllib.load(secrets_file)
    try:
        url = settings["supabase_url"]
        anon_key = settings["supabase_anon_key"]
        encryption_key = decode_encryption_key(settings["record_encryption_key"])
    except (KeyError, ValueError) as exc:
        print(f"Invalid app secrets: {exc}", file=sys.stderr)
        return 2

    if not args.workbook.is_file():
        print(f"Workbook not found: {args.workbook}", file=sys.stderr)
        return 2
    try:
        records = workbook_records(args.workbook)
    except (OSError, ValueError) as exc:
        print(f"Workbook could not be read: {exc}", file=sys.stderr)
        return 2
    if not records:
        print("The workbook contains no membership records.", file=sys.stderr)
        return 2

    client = create_client(url, anon_key)
    email = input("Admin/editor email: ").strip()
    password = getpass.getpass("Account password: ")
    try:
        auth = client.auth.sign_in_with_password({"email": email, "password": password})
        if auth.session is None:
            print("Supabase sign-in did not return a session.", file=sys.stderr)
            return 1
        existing = client.table("member_records").select("id").limit(1).execute()
        if existing.data:
            print(
                "Import stopped: the database already contains member records. "
                "This importer will not append duplicate workbook data.",
                file=sys.stderr,
            )
            return 1

        encrypted = []
        for record in records:
            record_id = str(uuid4())
            encrypted.append(
                {
                    "id": record_id,
                    "encrypted_payload": encrypt_record(
                        record, record_id, encryption_key
                    ),
                    "fields": encrypt_record_fields(
                        record, record_id, encryption_key
                    ),
                }
            )
        imported = client.rpc(
            "import_member_records", {"p_records": encrypted}
        ).execute()
        if imported.data != len(records):
            print(
                "Import did not confirm the expected record count; check the database before retrying.",
                file=sys.stderr,
            )
            return 1
    except Exception as exc:
        print(
            f"Import failed ({type(exc).__name__}). No partial import is expected; "
            "check Supabase access and the schema, then retry.",
            file=sys.stderr,
        )
        return 1
    print(f"Imported and encrypted {len(records)} membership records.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
