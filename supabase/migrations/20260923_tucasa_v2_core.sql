create extension if not exists pgcrypto;
create schema if not exists private;

create table if not exists public.profiles(
 id uuid primary key references auth.users(id) on delete cascade,
 username text not null unique,
 display_name text not null,
 email_added boolean not null default false,
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now(),
 constraint profiles_username_format check(username~'^[a-z0-9_]{3,24}$'),
 constraint profiles_display_name_length check(char_length(display_name) between 1 and 60)
);
create table if not exists public.parties(
 id uuid primary key default gen_random_uuid(),
 host_id uuid not null references public.profiles(id) on delete cascade,
 name text not null,
 location_name text not null,
 location_lat double precision,
 location_lng double precision,
 starts_at timestamptz not null,
 ends_at timestamptz,
 access_mode text not null default 'public' check(access_mode in('public','approval','code','private')),
 capacity integer check(capacity is null or capacity>0),
 description text,
 cover_path text,
 status text not null default 'upcoming' check(status in('upcoming','live','ended')),
 dump_visibility text not null default 'participants' check(dump_visibility in('participants','anyone')),
 party_code text not null unique,
 invite_token text not null unique,
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now()
);
create table if not exists public.party_memberships(
 id uuid primary key default gen_random_uuid(),
 party_id uuid not null references public.parties(id) on delete cascade,
 user_id uuid not null references public.profiles(id) on delete cascade,
 status text not null check(status in('requested','confirmed','rejected','left')),
 joined_at timestamptz not null default now(),
 updated_at timestamptz not null default now(),
 unique(party_id,user_id)
);
create table if not exists public.party_blocks(
 party_id uuid not null references public.parties(id) on delete cascade,
 user_id uuid not null references public.profiles(id) on delete cascade,
 blocked_by uuid not null references public.profiles(id) on delete cascade,
 created_at timestamptz not null default now(),
 primary key(party_id,user_id)
);
create table if not exists public.party_media(
 id uuid primary key default gen_random_uuid(),
 party_id uuid not null references public.parties(id) on delete cascade,
 uploader_id uuid not null references public.profiles(id) on delete cascade,
 storage_path text not null unique,
 media_type text not null check(media_type in('image','video')),
 duration_ms integer,
 caption text,
 created_at timestamptz not null default now()
);
create index if not exists parties_discover_idx on public.parties(status,starts_at desc);
create index if not exists memberships_party_idx on public.party_memberships(party_id,status);
create index if not exists memberships_user_idx on public.party_memberships(user_id,status);
create index if not exists media_party_idx on public.party_media(party_id,created_at desc);

create or replace function private.is_party_member(p uuid,u uuid) returns boolean language sql stable security definer set search_path='' as $$select exists(select 1 from public.party_memberships where party_id=p and user_id=u and status='confirmed')$$;
create or replace function private.is_party_host(p uuid,u uuid) returns boolean language sql stable security definer set search_path='' as $$select exists(select 1 from public.parties where id=p and host_id=u)$$;
create or replace function private.is_party_blocked(p uuid,u uuid) returns boolean language sql stable security definer set search_path='' as $$select exists(select 1 from public.party_blocks where party_id=p and user_id=u)$$;
create or replace function private.can_view_dump(p uuid,u uuid) returns boolean language sql stable security definer set search_path='' as $$select exists(select 1 from public.parties x where x.id=p and(x.dump_visibility='anyone' or x.host_id=u or private.is_party_member(p,u)))$$;
create or replace function private.can_join_discoverable(p uuid,u uuid,s text) returns boolean language sql stable security definer set search_path='' as $$select exists(select 1 from public.parties x where x.id=p and x.access_mode in('public','approval') and x.status<>'ended' and not exists(select 1 from public.party_blocks b where b.party_id=x.id and b.user_id=u) and(x.capacity is null or(select count(*) from public.party_memberships m where m.party_id=x.id and m.status='confirmed')<x.capacity) and((x.access_mode='public' and s='confirmed')or(x.access_mode='approval' and s='requested')))$$;

revoke execute on function private.is_party_member(uuid,uuid) from public;
revoke execute on function private.is_party_host(uuid,uuid) from public;
revoke execute on function private.is_party_blocked(uuid,uuid) from public;
revoke execute on function private.can_view_dump(uuid,uuid) from public;
revoke execute on function private.can_join_discoverable(uuid,uuid,text) from public;
grant usage on schema private to authenticated;
grant execute on function private.is_party_member(uuid,uuid),private.is_party_host(uuid,uuid),private.is_party_blocked(uuid,uuid),private.can_view_dump(uuid,uuid),private.can_join_discoverable(uuid,uuid,text) to authenticated;

alter table public.profiles enable row level security;
alter table public.parties enable row level security;
alter table public.party_memberships enable row level security;
alter table public.party_blocks enable row level security;
alter table public.party_media enable row level security;

revoke all on public.profiles,public.parties,public.party_memberships,public.party_blocks,public.party_media from anon;
grant select,insert,update on public.profiles to authenticated;
grant select,insert,update on public.parties to authenticated;
grant select,insert,update,delete on public.party_memberships to authenticated;
grant select,insert,delete on public.party_blocks to authenticated;
grant select,insert,update,delete on public.party_media to authenticated;

drop policy if exists "Profiles are visible to signed-in users" on public.profiles;
create policy "Profiles are visible to signed-in users" on public.profiles for select to authenticated using(true);
drop policy if exists "Users can update their own profile" on public.profiles;
create policy "Users can update their own profile" on public.profiles for update to authenticated using((select auth.uid())=id) with check((select auth.uid())=id);
drop policy if exists "Users can create their own profile" on public.profiles;
create policy "Users can create their own profile" on public.profiles for insert to authenticated with check((select auth.uid())=id);

drop policy if exists "Discoverable parties are visible" on public.parties;
create policy "Discoverable parties are visible" on public.parties for select to authenticated using(access_mode in('public','approval') or host_id=(select auth.uid()) or private.is_party_member(id,(select auth.uid())));
drop policy if exists "Users can create parties" on public.parties;
create policy "Users can create parties" on public.parties for insert to authenticated with check(host_id=(select auth.uid()));
drop policy if exists "Hosts can update parties" on public.parties;
create policy "Hosts can update parties" on public.parties for update to authenticated using(host_id=(select auth.uid())) with check(host_id=(select auth.uid()));

drop policy if exists "Members can view their memberships" on public.party_memberships;
create policy "Members can view their memberships" on public.party_memberships for select to authenticated using(user_id=(select auth.uid()) or private.is_party_host(party_id,(select auth.uid())) or private.is_party_member(party_id,(select auth.uid())));
drop policy if exists "Users can join discoverable parties" on public.party_memberships;
create policy "Users can join discoverable parties" on public.party_memberships for insert to authenticated with check(user_id=(select auth.uid()) and private.can_join_discoverable(party_id,(select auth.uid()),status));
drop policy if exists "Hosts can manage memberships" on public.party_memberships;
create policy "Hosts can manage memberships" on public.party_memberships for update to authenticated using(private.is_party_host(party_id,(select auth.uid()))) with check(private.is_party_host(party_id,(select auth.uid())));
drop policy if exists "Users can leave parties" on public.party_memberships;
create policy "Users can leave parties" on public.party_memberships for delete to authenticated using(user_id=(select auth.uid()) and not private.is_party_host(party_id,(select auth.uid())));
drop policy if exists "Hosts can delete memberships" on public.party_memberships;
create policy "Hosts can delete memberships" on public.party_memberships for delete to authenticated using(private.is_party_host(party_id,(select auth.uid())));

drop policy if exists "Hosts can view blocks" on public.party_blocks;
create policy "Hosts can view blocks" on public.party_blocks for select to authenticated using(private.is_party_host(party_id,(select auth.uid())));
drop policy if exists "Hosts can block participants" on public.party_blocks;
create policy "Hosts can block participants" on public.party_blocks for insert to authenticated with check(blocked_by=(select auth.uid()) and private.is_party_host(party_id,(select auth.uid())));
drop policy if exists "Hosts can unblock participants" on public.party_blocks;
create policy "Hosts can unblock participants" on public.party_blocks for delete to authenticated using(private.is_party_host(party_id,(select auth.uid())));

drop policy if exists "Participants can view party media" on public.party_media;
create policy "Participants can view party media" on public.party_media for select to authenticated using(private.can_view_dump(party_id,(select auth.uid())));
drop policy if exists "Participants can upload party media" on public.party_media;
create policy "Participants can upload party media" on public.party_media for insert to authenticated with check(uploader_id=(select auth.uid()) and private.is_party_member(party_id,(select auth.uid())) and exists(select 1 from public.parties p where p.id=party_id and p.status in('upcoming','live')));
drop policy if exists "Users can delete their own media" on public.party_media;
create policy "Users can delete their own media" on public.party_media for delete to authenticated using(uploader_id=(select auth.uid()) or private.is_party_host(party_id,(select auth.uid())));
drop policy if exists "Hosts can update party media" on public.party_media;
create policy "Hosts can update party media" on public.party_media for update to authenticated using(private.is_party_host(party_id,(select auth.uid()))) with check(private.is_party_host(party_id,(select auth.uid())));

insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types) values('party-media','party-media',false,52428800,array['image/jpeg','image/png','image/webp','image/heic','video/mp4','video/webm','video/quicktime']) on conflict(id) do update set public=false,file_size_limit=52428800,allowed_mime_types=excluded.allowed_mime_types;
drop policy if exists "Party participants can upload media" on storage.objects;
create policy "Party participants can upload media" on storage.objects for insert to authenticated with check(bucket_id='party-media' and private.is_party_member(split_part(name,'/',1)::uuid,(select auth.uid())));
drop policy if exists "Party participants can read media" on storage.objects;
create policy "Party participants can read media" on storage.objects for select to authenticated using(bucket_id='party-media' and exists(select 1 from public.party_media m where m.storage_path=name and private.can_view_dump(m.party_id,(select auth.uid()))));
drop policy if exists "Owners and hosts can delete media" on storage.objects;
create policy "Owners and hosts can delete media" on storage.objects for delete to authenticated using(bucket_id='party-media' and(owner_id=(select auth.uid())::text or exists(select 1 from public.party_media m where m.storage_path=name and private.is_party_host(m.party_id,(select auth.uid())))));
