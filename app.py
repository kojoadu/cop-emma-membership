"""Private Streamlit UI for COP EMMA membership management."""

from __future__ import annotations

import logging
from io import BytesIO
from typing import Any
from uuid import UUID, uuid4

import streamlit as st
from streamlit.errors import StreamlitSecretNotFoundError
from supabase import Client, create_client

from membership import (
    WORKBOOK_FIELDS,
    decrypt_record,
    decrypt_record_fields,
    decode_encryption_key,
    encrypt_record,
    encrypt_record_fields,
    membership_workbook,
    new_membership_records,
    search_records,
    workbook_records,
)

LOGGER = logging.getLogger("cop_emma_membership")
PAGE_SIZE = 500

st.set_page_config(page_title="COP EMMA MEMBERSHIP", page_icon="📋", layout="wide")


def _load_settings() -> tuple[str, str, bytes]:
    try:
        settings = {
            name: st.secrets.get(name)
            for name in ("supabase_url", "supabase_anon_key", "record_encryption_key")
        }
    except StreamlitSecretNotFoundError:
        st.error(
            "No Streamlit secrets were found. Create `.streamlit/secrets.toml` "
            "from `secrets.toml.example` before starting the app."
        )
        st.stop()
    missing = [name for name, value in settings.items() if not value]
    if missing:
        st.error(
            "The app is not configured. Add the required values to Streamlit secrets: "
            + ", ".join(missing)
        )
        st.stop()
    try:
        encryption_key = decode_encryption_key(settings["record_encryption_key"])
    except ValueError as exc:
        st.error(str(exc))
        st.stop()
    return settings["supabase_url"], settings["supabase_anon_key"], encryption_key


def _sync_tokens(client: Client) -> None:
    session = client.auth.get_session()
    if session is None:
        _clear_login_state()
        return
    st.session_state["access_token"] = session.access_token
    st.session_state["refresh_token"] = session.refresh_token


def _clear_login_state() -> None:
    for name in ("access_token", "refresh_token", "user_id", "email", "role"):
        st.session_state.pop(name, None)


def _authenticated_client(url: str, anon_key: str) -> Client | None:
    access_token = st.session_state.get("access_token")
    refresh_token = st.session_state.get("refresh_token")
    if not access_token or not refresh_token:
        return None
    client = create_client(url, anon_key)
    try:
        client.auth.set_session(access_token, refresh_token)
        _sync_tokens(client)
    except Exception as exc:
        LOGGER.warning("Supabase session restore failed (%s).", type(exc).__name__)
        _clear_login_state()
        st.warning("Your sign-in session expired. Sign in again to continue.")
        return None
    return client


def _sign_in(url: str, anon_key: str, email: str, password: str) -> None:
    client = create_client(url, anon_key)
    try:
        response = client.auth.sign_in_with_password(
            {"email": email.strip(), "password": password}
        )
        if response.session is None or response.user is None:
            st.error("Sign-in did not return an authenticated session.")
            return
        st.session_state["access_token"] = response.session.access_token
        st.session_state["refresh_token"] = response.session.refresh_token
        st.session_state["user_id"] = str(response.user.id)
        st.session_state["email"] = response.user.email or email.strip()
        _sync_tokens(client)
        st.rerun()
    except Exception as exc:
        LOGGER.warning("Supabase sign-in failed (%s).", type(exc).__name__)
        st.error("Sign-in failed. Check your email and password, then try again.")


def _get_role(client: Client) -> str | None:
    response = (
        client.table("user_roles")
        .select("role")
        .eq("user_id", st.session_state["user_id"])
        .maybe_single()
        .execute()
    )
    if response.data is None:
        return None
    role = response.data.get("role")
    return role if role in {"admin", "editor"} else None


def _fetch_records(client: Client, encryption_key: bytes) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    offset = 0
    while True:
        response = (
            client.table("member_records")
            .select(
                "id,encrypted_payload,"
                + ",".join(f'"{field}"' for field in WORKBOOK_FIELDS)
            )
            .order("id")
            .range(offset, offset + PAGE_SIZE - 1)
            .execute()
        )
        page = response.data or []
        for row in page:
            record_id = str(row["id"])
            encrypted_fields = {field: row.get(field) for field in WORKBOOK_FIELDS}
            if all(value is None for value in encrypted_fields.values()):
                record = decrypt_record(
                    row["encrypted_payload"], record_id, encryption_key
                )
            elif any(value is None for value in encrypted_fields.values()):
                raise ValueError(
                    "Membership record has an incomplete encrypted field set."
                )
            else:
                record = decrypt_record_fields(
                    encrypted_fields, record_id, encryption_key
                )
            record["_record_id"] = record_id
            records.append(record)
        if len(page) < PAGE_SIZE:
            return records
        offset += PAGE_SIZE


def _save_record(
    client: Client,
    encryption_key: bytes,
    record: dict[str, str],
    record_id: str,
) -> str:
    payload = encrypt_record(record, record_id, encryption_key)
    encrypted_fields = encrypt_record_fields(record, record_id, encryption_key)
    response = client.rpc(
        "save_member_record",
        {
            "p_record_id": record_id,
            "p_encrypted_payload": payload,
            "p_encrypted_fields": encrypted_fields,
        },
    ).execute()
    if str(response.data) != record_id:
        raise RuntimeError("The database did not confirm the requested record save.")
    return record_id


def _record_label(record: dict[str, Any]) -> str:
    name = " ".join(
        str(record.get(field, "")).strip()
        for field in ("FIRST NAME", "OTHER NAMES", "LAST NAME")
        if str(record.get(field, "")).strip()
    )
    residence = str(record.get("PLACE OF RESIDENCE", "")).strip()
    return f"{name or 'Unnamed member'}{f' · {residence}' if residence else ''}"


def _member_form(
    client: Client,
    key: bytes,
    record_id: str,
    initial: dict[str, Any],
    form_key: str,
    submit_label: str,
) -> None:
    with st.form(form_key):
        left, right = st.columns(2)
        edited: dict[str, str] = {}
        for index, field in enumerate(WORKBOOK_FIELDS):
            target = left if index % 2 == 0 else right
            value = initial.get(field, "")
            with target:
                edited[field] = st.text_input(
                    field,
                    value="" if value is None else str(value),
                    max_chars=2000,
                    key=f"{form_key}_{field}",
                )
        submitted = st.form_submit_button(submit_label, type="primary")
    if submitted:
        try:
            _save_record(client, key, edited, record_id)
        except Exception as exc:
            LOGGER.error("Member record save failed (%s).", type(exc).__name__)
            st.error("The record could not be saved. No changes were reported as complete.")
            return
        st.success("Member record saved.")
        st.rerun()


def _search_tab(
    client: Client, key: bytes, records: list[dict[str, Any]]
) -> None:
    query = st.text_input(
        "Search members",
        placeholder="Search across member fields",
        help="Search is performed in app memory after authorized records are decrypted.",
    )
    matches = search_records(records, query)
    st.caption(f"{len(matches)} matching member(s)")
    st.dataframe(
        [
            {field: record.get(field, "") for field in WORKBOOK_FIELDS}
            for record in matches
        ],
        hide_index=True,
        width="stretch",
        alt="Matching member records showing all 33 member-detail fields",
    )
    if not matches:
        return
    by_id = {record["_record_id"]: record for record in matches}
    selected_id = st.selectbox(
        "Select a member to edit",
        options=list(by_id),
        format_func=lambda item: _record_label(by_id[item]),
    )
    _member_form(
        client,
        key,
        selected_id,
        by_id[selected_id],
        f"edit_{selected_id}",
        "Save member changes",
    )


def _add_tab(client: Client, key: bytes) -> None:
    st.caption("Enter the member details. All fields are encrypted before they are saved.")
    _member_form(
        client,
        key,
        str(uuid4()),
        {},
        "add_member",
        "Add member",
    )


def _audit_tab(client: Client, key: bytes) -> None:
    offset = st.session_state.setdefault("audit_offset", 0)
    response = (
        client.table("member_audit")
        .select(
            "id,record_id,actor_id,action,before_ciphertext,after_ciphertext,created_at",
            count="exact",
        )
        .order("created_at", desc=True)
        .order("id", desc=True)
        .range(offset, offset + 99)
        .execute()
    )
    entries = response.data or []
    total = response.count or 0
    if offset >= total and total:
        st.session_state["audit_offset"] = max(0, ((total - 1) // 100) * 100)
        st.rerun()
    if not total:
        st.info("No changes have been recorded yet.")
        return
    previous, page_info, following = st.columns((1, 3, 1))
    with previous:
        if st.button("Newer", disabled=offset == 0):
            st.session_state["audit_offset"] = max(0, offset - 100)
            st.rerun()
    with page_info:
        st.caption(f"Showing changes {offset + 1}–{min(offset + 100, total)} of {total}")
    with following:
        if st.button("Older", disabled=offset + 100 >= total):
            st.session_state["audit_offset"] = offset + 100
            st.rerun()
    choices = {str(entry["id"]): entry for entry in entries}
    selected = st.selectbox(
        "Recent record changes",
        options=list(choices),
        format_func=lambda item: (
            f"{choices[item]['created_at']} · {choices[item]['action']} · "
            f"{choices[item]['actor_id']}"
        ),
    )
    entry = choices[selected]
    st.caption(f"Member record: {entry['record_id']}")
    try:
        for label, column in (
            ("Before", "before_ciphertext"),
            ("After", "after_ciphertext"),
        ):
            ciphertext = entry.get(column)
            if ciphertext is not None:
                st.subheader(label)
                st.json(decrypt_record(ciphertext, entry["record_id"], key))
    except ValueError as exc:
        LOGGER.error("Audit record decryption failed (%s).", type(exc).__name__)
        st.error(str(exc))


def _admin_tab(
    client: Client, key: bytes, records: list[dict[str, Any]]
) -> None:
    imported_count = st.session_state.pop("bulk_import_result", None)
    if imported_count is not None:
        st.success(f"Imported {imported_count} new member record(s).")

    st.subheader("Export member data")
    st.caption(
        "Download every member record and all 33 detail fields as an Excel workbook."
    )
    try:
        workbook = membership_workbook(records)
    except Exception as exc:
        LOGGER.error("Membership workbook export failed (%s).", type(exc).__name__)
        st.error("Member data export could not be prepared.")
    else:
        st.download_button(
            "Download all member data",
            data=workbook,
            file_name="cop-emma-membership.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            help="The workbook uses the same layout as the membership backfill importer.",
        )

    st.divider()
    st.subheader("Bulk import member data")
    st.caption(
        "Upload a membership workbook with the standard blank leading column and "
        "33 member-detail fields. Exact matches are skipped."
    )
    uploaded_file = st.file_uploader(
        "Membership workbook",
        type=["xlsx"],
        max_upload_size=10,
        key="bulk_membership_workbook",
        help="Maximum file size: 10 MB.",
    )
    if uploaded_file is not None:
        try:
            candidate_records = workbook_records(BytesIO(uploaded_file.getvalue()))
        except Exception as exc:
            LOGGER.error("Membership workbook upload failed (%s).", type(exc).__name__)
            st.error(
                "The uploaded workbook could not be read. Check that it uses the "
                "membership workbook layout and is a valid .xlsx file."
            )
        else:
            new_records = new_membership_records(records, candidate_records)
            st.caption(
                f"{len(candidate_records)} non-empty row(s) found; "
                f"{len(new_records)} new row(s) will be imported."
            )
            if not new_records:
                st.info("There are no new member records to import.")
            elif len(new_records) > 1000:
                st.error(
                    "This import exceeds the 1,000-record limit. Split the workbook "
                    "into smaller files and upload them separately."
                )
            elif st.button("Import new members", type="primary"):
                try:
                    encrypted_records = []
                    for record in new_records:
                        record_id = str(uuid4())
                        encrypted_records.append(
                            {
                                "id": record_id,
                                "encrypted_payload": encrypt_record(
                                    record, record_id, key
                                ),
                                "fields": encrypt_record_fields(
                                    record, record_id, key
                                ),
                            }
                        )
                    response = client.rpc(
                        "import_member_records",
                        {"p_records": encrypted_records},
                    ).execute()
                    if (
                        not isinstance(response.data, int)
                        or response.data != len(new_records)
                    ):
                        raise RuntimeError(
                            "The database did not confirm the expected import count."
                        )
                except Exception as exc:
                    LOGGER.error(
                        "Membership bulk import failed (%s).", type(exc).__name__
                    )
                    st.error(
                        "The member import could not be confirmed. Refresh the page "
                        "before retrying to check whether any records were added."
                    )
                else:
                    st.session_state["bulk_import_result"] = response.data
                    st.rerun()

    st.divider()
    st.subheader("User roles")
    response = (
        client.table("user_roles")
        .select("user_id,role")
        .order("user_id")
        .execute()
    )
    st.dataframe(
        response.data or [],
        hide_index=True,
        width="stretch",
        alt="Membership app user roles",
    )
    st.caption(
        "Invite email/password users from Supabase Dashboard → Authentication → Users. "
        "After invitation, assign or change their app role below using their Supabase user ID."
    )
    with st.form("assign_role"):
        target_id = st.text_input("Supabase user ID", max_chars=36)
        role = st.selectbox("Role", ("editor", "admin"))
        submitted = st.form_submit_button("Set role")
    if submitted:
        try:
            normalized_id = str(UUID(target_id.strip()))
            client.rpc(
                "admin_set_user_role",
                {"p_user_id": normalized_id, "p_role": role},
            ).execute()
            st.success("User role updated.")
            st.rerun()
        except ValueError:
            st.error("Enter a valid Supabase user UUID.")
        except Exception as exc:
            LOGGER.error("Role update failed (%s).", type(exc).__name__)
            st.error("Role update failed. Confirm the user exists and your admin role.")


def main() -> None:
    st.title("COP EMMA MEMBERSHIP")
    st.caption("Private member directory")
    url, anon_key, encryption_key = _load_settings()
    client = _authenticated_client(url, anon_key)
    if client is None:
        with st.form("sign_in"):
            email = st.text_input("Email", autocomplete="email")
            password = st.text_input(
                "Password", type="password", autocomplete="current-password"
            )
            submitted = st.form_submit_button("Sign in", type="primary")
        if submitted:
            _sign_in(url, anon_key, email, password)
        st.info("Accounts are provisioned by an administrator; public sign-up is disabled.")
        return

    try:
        role = _get_role(client)
        _sync_tokens(client)
    except Exception as exc:
        LOGGER.error("User authorization lookup failed (%s).", type(exc).__name__)
        st.error("Your account could not be authorized. Contact an administrator.")
        return
    if role is None:
        st.error("This account has no membership-app role. Contact an administrator.")
        with st.sidebar:
            st.write(st.session_state.get("email", "Signed-in user"))
            if st.button("Sign out"):
                try:
                    client.auth.sign_out()
                except Exception as exc:
                    LOGGER.warning("Supabase sign-out failed (%s).", type(exc).__name__)
                _clear_login_state()
                st.rerun()
        return
    st.session_state["role"] = role
    with st.sidebar:
        st.write(st.session_state.get("email", "Signed-in user"))
        st.caption(f"Role: {role}")
        if st.button("Sign out"):
            try:
                client.auth.sign_out()
            except Exception as exc:
                LOGGER.warning("Supabase sign-out failed (%s).", type(exc).__name__)
            _clear_login_state()
            st.rerun()

    try:
        records = _fetch_records(client, encryption_key)
    except ValueError as exc:
        LOGGER.error("Membership data integrity check failed (%s).", type(exc).__name__)
        st.error(str(exc))
        st.stop()
    except Exception as exc:
        LOGGER.error("Membership data load failed (%s).", type(exc).__name__)
        st.error("Member data could not be loaded. Check the Supabase schema and access policies.")
        st.stop()

    st.caption(f"{len(records)} member record(s)")
    tab_names = ["Search & edit", "Add member", "Change history"]
    if role == "admin":
        tab_names.append("Admin users")
    tabs = st.tabs(tab_names)
    with tabs[0]:
        _search_tab(client, encryption_key, records)
    with tabs[1]:
        _add_tab(client, encryption_key)
    with tabs[2]:
        try:
            _audit_tab(client, encryption_key)
        except Exception as exc:
            LOGGER.error("Audit history load failed (%s).", type(exc).__name__)
            st.error("Change history could not be loaded.")
    if role == "admin":
        with tabs[3]:
            try:
                _admin_tab(client, encryption_key, records)
            except Exception as exc:
                LOGGER.error("Admin role listing failed (%s).", type(exc).__name__)
                st.error("User roles could not be loaded.")


if __name__ == "__main__":
    main()
