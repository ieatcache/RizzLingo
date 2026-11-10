-- RizzLingo: lets Dave's spare sunglasses show next to a name on the leaderboard.
alter table public.players add column if not exists shades boolean not null default false;
