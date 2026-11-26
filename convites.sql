-- Cadastro só por convite. Rode UMA vez no Supabase: SQL Editor > New query > Run.
create table if not exists public.invite_codes(
  code text primary key,
  note text default '',
  created_by uuid default auth.uid(),
  created_at timestamptz default now(),
  expires_at timestamptz,
  used_by uuid,
  used_email text,
  used_at timestamptz
);
alter table public.invite_codes enable row level security;
drop policy if exists invite_admin_all on public.invite_codes;
create policy invite_admin_all on public.invite_codes for all to authenticated
  using (exists(select 1 from public.admins a where a.user_id=auth.uid()))
  with check (exists(select 1 from public.admins a where a.user_id=auth.uid()));

create or replace function public.nx_check_invite() returns trigger
language plpgsql security definer set search_path=public as $$
declare c text; n int;
begin
  c:=regexp_replace(upper(coalesce(new.raw_user_meta_data->>'invite','')),'[^A-Z0-9]','','g');
  if c='' then raise exception 'invite_required'; end if;
  update public.invite_codes set used_by=new.id, used_email=new.email, used_at=now()
   where code=c and used_by is null and (expires_at is null or expires_at>now());
  get diagnostics n=row_count;
  if n=0 then raise exception 'invite_invalid'; end if;
  new.raw_user_meta_data := new.raw_user_meta_data - 'invite';
  return new;
end $$;

drop trigger if exists nx_invite_gate on auth.users;
create trigger nx_invite_gate before insert on auth.users
  for each row execute function public.nx_check_invite();
