-- カード明細集計（okozukai-cho）用テーブル
-- Supabase の SQL Editor で 1 回実行する。何回実行しても大丈夫（if not exists / or replace）。
--
-- * 既存のおかいものメモのテーブルには一切さわらない。新しいテーブルはすべて cc_ ではじまる。
-- * 3 テーブルとも RLS を有効にして「ログインした本人の行だけ」読める・書ける。
--   anon キーを知っていても、ログインしていなければ 1 行も読めない。

-- 種別マスタ（1人1行。中身は {axes: [...], rows: [{pattern, name, cats: [...]}]}）
create table if not exists cc_master (
  user_id    uuid primary key default auth.uid() references auth.users on delete cascade,
  data       jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

-- 取りこんだ明細書（カードは 請求月、マネーフォワードは 利用月 ごとに 1 行）
create table if not exists cc_imports (
  user_id     uuid not null default auth.uid() references auth.users on delete cascade,
  source      text not null,          -- 'Mastercard' | 'VISA' | 'Olive' | 'MF'
  claim       text not null,          -- 'YYYY-MM'
  kind        text,                   -- 'pending'(確定前) | 'confirmed'(確定後) | 'mixed' | 'mf'
  bill_total  integer,                -- 確定後CSVの最後の行のご請求額（なければ null）
  row_sum     integer,
  row_count   integer,
  file_name   text,
  imported_at timestamptz not null default now(),
  primary key (user_id, source, claim)
);

-- 明細
create table if not exists cc_tx (
  id       bigint generated always as identity primary key,
  user_id  uuid not null default auth.uid() references auth.users on delete cascade,
  source   text not null,
  claim    text not null,
  label    text not null,             -- カード名 / MFの種別（三井住友カード など）
  use_date date not null,
  store    text not null default '',
  amount   integer not null
);
create index if not exists cc_tx_user_source_claim on cc_tx (user_id, source, claim);

alter table cc_master  enable row level security;
alter table cc_imports enable row level security;
alter table cc_tx      enable row level security;

drop policy if exists cc_master_own  on cc_master;
drop policy if exists cc_imports_own on cc_imports;
drop policy if exists cc_tx_own      on cc_tx;
create policy cc_master_own  on cc_master  for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy cc_imports_own on cc_imports for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy cc_tx_own      on cc_tx      for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

-- 明細書の置きかえ（消す→入れる を 1 つのトランザクションで。途中で失敗したら何も変わらない）
-- security invoker なので RLS がそのまま効く＝自分の行しかさわれない。
create or replace function cc_replace_statement(p_source text, p_claims text[], p_rows jsonb, p_imports jsonb)
returns void language plpgsql security invoker set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  delete from cc_tx      where user_id = auth.uid() and source = p_source and claim = any(p_claims);
  delete from cc_imports where user_id = auth.uid() and source = p_source and claim = any(p_claims);
  insert into cc_tx (source, claim, label, use_date, store, amount)
    select p_source, r->>'claim', r->>'label', (r->>'date')::date, coalesce(r->>'store', ''), round((r->>'amount')::numeric)::int
    from jsonb_array_elements(p_rows) r;
  insert into cc_imports (source, claim, kind, bill_total, row_sum, row_count, file_name)
    select p_source, i->>'claim', i->>'kind', (i->>'bill_total')::int, (i->>'row_sum')::int, (i->>'row_count')::int, i->>'file_name'
    from jsonb_array_elements(p_imports) i;
end $$;

create or replace function cc_delete_statement(p_source text, p_claim text)
returns void language plpgsql security invoker set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  delete from cc_tx      where user_id = auth.uid() and source = p_source and claim = p_claim;
  delete from cc_imports where user_id = auth.uid() and source = p_source and claim = p_claim;
end $$;

revoke all on function cc_replace_statement(text, text[], jsonb, jsonb) from public, anon;
revoke all on function cc_delete_statement(text, text) from public, anon;
grant execute on function cc_replace_statement(text, text[], jsonb, jsonb) to authenticated;
grant execute on function cc_delete_statement(text, text) to authenticated;
