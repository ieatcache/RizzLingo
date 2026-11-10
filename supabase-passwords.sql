-- RizzLingo: passwords so players can sign out and back in.
-- Open a NEW query in the Supabase SQL Editor, paste all of this, click Run.
create extension if not exists pgcrypto with schema extensions;

create table if not exists public.player_secrets (
  player_id uuid primary key references public.players(id) on delete cascade on update cascade,
  pass_hash text not null
);
alter table public.player_secrets enable row level security;
-- No policies on purpose: nobody can read this table. Only the functions below use it.

create or replace function public.join_board(p_username text, p_password text, p_xp integer)
returns void language plpgsql security definer set search_path = public, extensions as $$
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  if length(p_password) < 4 or length(p_password) > 72 then raise exception 'bad password'; end if;
  insert into players (id, username, xp)
    values (auth.uid(), p_username, greatest(0, least(coalesce(p_xp, 0), 1000000)));
  insert into player_secrets (player_id, pass_hash)
    values (auth.uid(), crypt(p_password, gen_salt('bf')));
end $$;

create or replace function public.set_password(p_password text)
returns void language plpgsql security definer set search_path = public, extensions as $$
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  if length(p_password) < 4 or length(p_password) > 72 then raise exception 'bad password'; end if;
  if not exists (select 1 from players where id = auth.uid()) then raise exception 'no account'; end if;
  insert into player_secrets (player_id, pass_hash)
    values (auth.uid(), crypt(p_password, gen_salt('bf')))
    on conflict (player_id) do update set pass_hash = excluded.pass_hash;
end $$;

create or replace function public.has_password()
returns boolean language sql security definer set search_path = public as $$
  select exists (select 1 from player_secrets where player_id = auth.uid());
$$;

create or replace function public.sign_in(p_username text, p_password text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare pid uuid;
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  select p.id into pid
    from players p join player_secrets s on s.player_id = p.id
    where lower(p.username) = lower(p_username) and s.pass_hash = crypt(p_password, s.pass_hash);
  if pid is null then raise exception 'wrong username or password'; end if;
  if pid <> auth.uid() then
    delete from players where id = auth.uid();
    update players set id = auth.uid() where id = pid;
  end if;
  return (select json_build_object('username', p.username, 'xp', p.xp) from players p where p.id = auth.uid());
end $$;
