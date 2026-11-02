# [web] Springing

> Spring Security の `/admin/*`（1階層）と `/admin/users/{id}`（2階層）のマッチ差で認可が漏れる。

## Overview

| Item | Value |
|------|-------|
| Platform | AlpacaHack |
| Event | Daily Challenge |
| Category | web (Spring Security) |
| Difficulty | Misc/Web (Medium) |
| Date | 2026-11-03 |
| Released | 2026-09 |
| Flag | `Alpaca{p0yoyoyoyoyoyo----n}` |

## Problem Statement

Spring Boot + Spring Security のユーザ管理アプリ。`/admin` に flag。配布: ソース一式。

## TL;DR

- `SecurityConfig`:
  ```java
  .requestMatchers("/admin", "/admin/*").hasRole("ADMIN")
  .anyRequest().authenticated()
  ```
- ロール変更は `POST /admin/users/{userid}`（**2階層**）。`"/admin/*"` は**1階層**しか
  マッチしないので、この endpoint は `anyRequest().authenticated()` 扱い。
- 一般ユーザ(GUEST)が自分の userId を `role=ADMIN` に変更できる → 再ログインで ADMIN
  authority を得て `/admin` から flag。

## Background Knowledge

### Ant/MVC パターンの `*` は1セグメント

Spring の `requestMatchers("/admin/*")` の `*` は**スラッシュを跨がない**＝1階層のみ。
`/admin/users`(1階層) は保護されるが、`/admin/users/{id}`(2階層) は対象外。
全階層を守るなら `/admin/**` を使う必要がある。これが今回の認可バイパス。

### セッションの権限は login 時に確定

`UserService.loadUserByUsername` が role を読んで authority を組むのは**ログイン時**。
ストア上の role を書き換えただけでは既存セッションは GUEST のまま。昇格後に
**再ログイン**して authority を更新する必要がある。

## Solution

```
1. POST /user/register  (username, password)       # GUEST 作成
2. POST /user/login     (CSRF 無効)                 # session1
3. GET  /                -> "Your ID is <uuid>"      # 自分の userId
4. POST /admin/users/<uuid>  role=ADMIN             # /admin/* に非マッチ=認可漏れ
5. POST /user/login (再)                            # session2 = ROLE_ADMIN
6. GET  /admin           -> Alpaca{...}
```

実装は `solve.py`（標準 urllib + CookieJar）。手順4の 303 リダイレクト先 `/admin/users`
は ADMIN 必須で 403 になるが、ロール変更自体は成功している。

## Lessons Learned

- URL ベース認可は「パターンの網羅性」が命。`/admin/*` と `/admin/**` の違いで穴が開く。
  可能ならメソッドセキュリティ(`@PreAuthorize`)で縦深防御する。
- 状態変更後は権限の再評価（再ログイン/セッション更新）が要る点も実務的な学び。

## Tags

`web` `spring-security` `authorization-bypass` `ant-matcher` `privilege-escalation`
