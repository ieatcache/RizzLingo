-- RizzLingo leaderboard. Paste into the Supabase SQL Editor and click Run.
create table public.players (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null check (username ~ '^[A-Za-z0-9_]{3,16}$'),
  xp integer not null default 0 check (xp between 0 and 1000000),
  updated_at timestamptz not null default now()
);
create unique index players_username_lower on public.players (lower(username));
alter table public.players enable row level security;
create policy "Anyone can read the board" on public.players for select using (true);
create policy "Players add their own row" on public.players for insert to authenticated with check (auth.uid() = id);
create policy "Players update their own row" on public.players for update to authenticated using (auth.uid() = id) with check (auth.uid() = id);

-- Added for "Delete account": lets a player remove their own row.
create policy "Players delete their own row" on public.players for delete to authenticated using (auth.uid() = id);
