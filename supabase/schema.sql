-- Apply once in Supabase SQL Editor before deploying the Streamlit app.
-- The first admin is bootstrapped separately after creating their Auth user.

create table if not exists public.user_roles (
    user_id uuid primary key references auth.users(id) on delete restrict,
    role text not null check (role in ('admin', 'editor')),
    created_at timestamptz not null default now()
);

create table if not exists public.member_records (
    id uuid primary key,
    encrypted_payload text not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

alter table public.member_records
    add column if not exists "FIRST NAME" text,
    add column if not exists "LAST NAME" text,
    add column if not exists "OTHER NAMES" text,
    add column if not exists "DATE OF BIRTH" text,
    add column if not exists "HOMETOWN" text,
    add column if not exists "POSTAL ADDRESS" text,
    add column if not exists "PHONE 1" text,
    add column if not exists "PHONE 2" text,
    add column if not exists "E-MAIL" text,
    add column if not exists "PLACE OF RESIDENCE" text,
    add column if not exists "STREET NAME" text,
    add column if not exists "HOUSE NUMBER" text,
    add column if not exists "RESIDENT DIRECTION" text,
    add column if not exists "EDUCATIONAL LEVEL" text,
    add column if not exists "OCCUPATION" text,
    add column if not exists "FATHER" text,
    add column if not exists "FATHER CONTACT" text,
    add column if not exists "MOTHER" text,
    add column if not exists "MOTHER CONTACT" text,
    add column if not exists "MARITAL STATUS" text,
    add column if not exists "SPOUSE NAME" text,
    add column if not exists "SPOUSE CONTACT" text,
    add column if not exists "POSITION" text,
    add column if not exists "TRANSFERRED FROM" text,
    add column if not exists "TRANSFERRED DATE" text,
    add column if not exists "BAPTIZED BY" text,
    add column if not exists "BAPTIZED DATE" text,
    add column if not exists "PLACE BAPTIZED" text,
    add column if not exists "MINISTRY" text,
    add column if not exists "COMMUNICANT" text,
    add column if not exists "GENDER" text,
    add column if not exists "ACTIVE" text,
    add column if not exists "INACTIVE" text;

create table if not exists public.member_audit (
    id bigint generated always as identity primary key,
    record_id uuid not null references public.member_records(id) on delete restrict,
    actor_id uuid not null references auth.users(id) on delete restrict,
    action text not null check (action in ('insert', 'update')),
    before_ciphertext text,
    after_ciphertext text not null,
    created_at timestamptz not null default now()
);

create index if not exists member_audit_record_created_idx
    on public.member_audit (record_id, created_at desc);

alter table public.user_roles enable row level security;
alter table public.member_records enable row level security;
alter table public.member_audit enable row level security;

create or replace function public.current_user_role()
returns text
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
    select role
    from public.user_roles
    where user_id = (select auth.uid())
$$;

revoke all on function public.current_user_role() from public, anon;
grant execute on function public.current_user_role() to authenticated;

grant usage on schema public to authenticated;

drop policy if exists user_roles_read on public.user_roles;
create policy user_roles_read on public.user_roles
    for select to authenticated
    using (user_id = (select auth.uid()) or public.current_user_role() = 'admin');

drop policy if exists member_records_read on public.member_records;
create policy member_records_read on public.member_records
    for select to authenticated
    using (public.current_user_role() in ('admin', 'editor'));

drop policy if exists member_audit_read on public.member_audit;
create policy member_audit_read on public.member_audit
    for select to authenticated
    using (public.current_user_role() in ('admin', 'editor'));

revoke all on table public.user_roles from public, anon, authenticated;
revoke all on table public.member_records from public, anon, authenticated;
revoke all on table public.member_audit from public, anon, authenticated;
grant select on table public.user_roles to authenticated;
grant select on table public.member_records to authenticated;
grant select on table public.member_audit to authenticated;

drop function if exists public.save_member_record(uuid, text);

create or replace function public.save_member_record(
    p_record_id uuid,
    p_encrypted_payload text,
    p_encrypted_fields jsonb
)
returns uuid
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
    existing_payload text;
    change_action text;
    field_names text[] := array[
        'FIRST NAME', 'LAST NAME', 'OTHER NAMES', 'DATE OF BIRTH', 'HOMETOWN',
        'POSTAL ADDRESS', 'PHONE 1', 'PHONE 2', 'E-MAIL', 'PLACE OF RESIDENCE',
        'STREET NAME', 'HOUSE NUMBER', 'RESIDENT DIRECTION', 'EDUCATIONAL LEVEL',
        'OCCUPATION', 'FATHER', 'FATHER CONTACT', 'MOTHER', 'MOTHER CONTACT',
        'MARITAL STATUS', 'SPOUSE NAME', 'SPOUSE CONTACT', 'POSITION',
        'TRANSFERRED FROM', 'TRANSFERRED DATE', 'BAPTIZED BY', 'BAPTIZED DATE',
        'PLACE BAPTIZED', 'MINISTRY', 'COMMUNICANT', 'GENDER', 'ACTIVE', 'INACTIVE'
    ];
    quoted_columns text;
    encrypted_values text;
    encrypted_assignments text;
begin
    if coalesce((select public.current_user_role()), '') not in ('admin', 'editor') then
        raise exception 'Insufficient membership role' using errcode = '42501';
    end if;
    if p_record_id is null
       or p_encrypted_payload is null
       or length(p_encrypted_payload) > 1048576
       or p_encrypted_payload !~ '^v1:[A-Za-z0-9_=-]+$'
       or p_encrypted_fields is null
       or jsonb_typeof(p_encrypted_fields) is distinct from 'object'
       or (select count(*) from jsonb_object_keys(p_encrypted_fields)) <> 33
       or exists (
            select 1
            from unnest(field_names) as expected(field_name)
            where not (p_encrypted_fields ? expected.field_name)
               or jsonb_typeof(p_encrypted_fields -> expected.field_name) is distinct from 'string'
               or length(p_encrypted_fields ->> expected.field_name) > 4096
               or p_encrypted_fields ->> expected.field_name !~ '^v1:[A-Za-z0-9_=-]+$'
       ) then
        raise exception 'Invalid encrypted membership payload' using errcode = '22023';
    end if;

    select encrypted_payload
      into existing_payload
      from public.member_records
     where id = p_record_id
     for update;

    if found then
        change_action := 'update';
        select string_agg(format('%I', field_name), ', ' order by ordinal),
               string_agg(format('%I = $3 ->> %L', field_name, field_name), ', ' order by ordinal)
          into quoted_columns, encrypted_assignments
          from unnest(field_names) with ordinality as fields(field_name, ordinal);
        execute format(
            'update public.member_records set encrypted_payload = $1, updated_at = now(), %s where id = $2',
            encrypted_assignments
        ) using p_encrypted_payload, p_record_id, p_encrypted_fields;
    else
        change_action := 'insert';
        select string_agg(format('%I', field_name), ', ' order by ordinal),
               string_agg(format('($3 ->> %L)', field_name), ', ' order by ordinal)
          into quoted_columns, encrypted_values
          from unnest(field_names) with ordinality as fields(field_name, ordinal);
        execute format(
            'insert into public.member_records (id, encrypted_payload, %s) values ($1, $2, %s)',
            quoted_columns,
            encrypted_values
        ) using p_record_id, p_encrypted_payload, p_encrypted_fields;
    end if;

    insert into public.member_audit (
        record_id,
        actor_id,
        action,
        before_ciphertext,
        after_ciphertext
    )
    values (
        p_record_id,
        (select auth.uid()),
        change_action,
        existing_payload,
        p_encrypted_payload
    );

    return p_record_id;
end;
$$;

revoke all on function public.save_member_record(uuid, text, jsonb) from public, anon;
grant execute on function public.save_member_record(uuid, text, jsonb) to authenticated;

create or replace function public.import_member_records(p_records jsonb)
returns integer
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
    item jsonb;
    imported_count integer := 0;
    record_id uuid;
    encrypted_payload text;
    encrypted_fields jsonb;
    field_names text[] := array[
        'FIRST NAME', 'LAST NAME', 'OTHER NAMES', 'DATE OF BIRTH', 'HOMETOWN',
        'POSTAL ADDRESS', 'PHONE 1', 'PHONE 2', 'E-MAIL', 'PLACE OF RESIDENCE',
        'STREET NAME', 'HOUSE NUMBER', 'RESIDENT DIRECTION', 'EDUCATIONAL LEVEL',
        'OCCUPATION', 'FATHER', 'FATHER CONTACT', 'MOTHER', 'MOTHER CONTACT',
        'MARITAL STATUS', 'SPOUSE NAME', 'SPOUSE CONTACT', 'POSITION',
        'TRANSFERRED FROM', 'TRANSFERRED DATE', 'BAPTIZED BY', 'BAPTIZED DATE',
        'PLACE BAPTIZED', 'MINISTRY', 'COMMUNICANT', 'GENDER', 'ACTIVE', 'INACTIVE'
    ];
    quoted_columns text;
    encrypted_values text;
begin
    if coalesce((select public.current_user_role()), '') <> 'admin' then
        raise exception 'Insufficient membership role' using errcode = '42501';
    end if;
    if p_records is null or jsonb_typeof(p_records) is distinct from 'array' then
        raise exception 'Import must be a JSON array'
            using errcode = '22023';
    end if;
    if jsonb_array_length(p_records) = 0
       or jsonb_array_length(p_records) > 1000 then
        raise exception 'Import must contain between 1 and 1000 records'
            using errcode = '22023';
    end if;
    for item in select value from jsonb_array_elements(p_records)
    loop
        record_id := (item ->> 'id')::uuid;
        encrypted_payload := item ->> 'encrypted_payload';
        encrypted_fields := item -> 'fields';
        if record_id is null
           or encrypted_payload is null
           or length(encrypted_payload) > 1048576
           or encrypted_payload !~ '^v1:[A-Za-z0-9_=-]+$'
           or encrypted_fields is null
           or jsonb_typeof(encrypted_fields) is distinct from 'object'
           or (select count(*) from jsonb_object_keys(encrypted_fields)) <> 33
           or exists (
                select 1
                from unnest(field_names) as expected(field_name)
                where not (encrypted_fields ? expected.field_name)
                   or jsonb_typeof(encrypted_fields -> expected.field_name) is distinct from 'string'
                   or length(encrypted_fields ->> expected.field_name) > 4096
                   or encrypted_fields ->> expected.field_name !~ '^v1:[A-Za-z0-9_=-]+$'
           ) then
            raise exception 'Invalid encrypted membership payload' using errcode = '22023';
        end if;

        select string_agg(format('%I', field_name), ', ' order by ordinal),
               string_agg(format('($1 ->> %L)', field_name), ', ' order by ordinal)
          into quoted_columns, encrypted_values
          from unnest(field_names) with ordinality as fields(field_name, ordinal);
        execute format(
            'insert into public.member_records (id, encrypted_payload, %s) values ($2, $3, %s)',
            quoted_columns,
            encrypted_values
        ) using encrypted_fields, record_id, encrypted_payload;
        insert into public.member_audit (
            record_id,
            actor_id,
            action,
            after_ciphertext
        )
        values (
            record_id,
            (select auth.uid()),
            'insert',
            encrypted_payload
        );
        imported_count := imported_count + 1;
    end loop;

    return imported_count;
end;
$$;

revoke all on function public.import_member_records(jsonb) from public, anon;
grant execute on function public.import_member_records(jsonb) to authenticated;

create or replace function public.admin_set_user_role(
    p_user_id uuid,
    p_role text
)
returns void
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
    admin_count bigint;
begin
    perform pg_advisory_xact_lock(hashtextextended('membership-admin-role-change', 0));
    if (select public.current_user_role()) is distinct from 'admin' then
        raise exception 'Insufficient membership role' using errcode = '42501';
    end if;
    if p_user_id is null or p_role is null or p_role not in ('admin', 'editor') then
        raise exception 'Invalid membership role assignment' using errcode = '22023';
    end if;
    if p_user_id = (select auth.uid()) and p_role <> 'admin' then
        raise exception 'An admin cannot demote their own account' using errcode = '22023';
    end if;
    if p_role <> 'admin' then
        select count(*) into admin_count
          from public.user_roles
         where role = 'admin';
        if (select role from public.user_roles where user_id = p_user_id) = 'admin'
           and admin_count <= 1 then
            raise exception 'The last admin cannot be demoted' using errcode = '22023';
        end if;
    end if;

    insert into public.user_roles (user_id, role)
    values (p_user_id, p_role)
    on conflict (user_id) do update set role = excluded.role;
end;
$$;

revoke all on function public.admin_set_user_role(uuid, text) from public, anon;
grant execute on function public.admin_set_user_role(uuid, text) to authenticated;

-- Bootstrap the first admin manually after creating/inviting that account in
-- Supabase Authentication. Replace the UUID with the Auth user's actual ID:
-- insert into public.user_roles (user_id, role)
-- values ('00000000-0000-0000-0000-000000000000', 'admin');
