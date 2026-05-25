"""Contributor referral tracking for BLT-Pool.

Handles detecting @-mentions of new contributors in issue/PR comments,
recording referrals in D1, and posting congratulatory leaderboard comments.
"""
import json
import re
from typing import Optional

from js import console

from core.db import _d1_binding, _d1_all, _d1_first, _month_key
from core.github_client import github_api, create_comment
from models.leaderboard import _ensure_leaderboard_schema

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REFERRAL_MARKER = "<!-- blt-referral-bot -->"
MAX_REFERRAL_MENTIONS_PER_COMMENT = 5

_MENTION_RE = re.compile(r"(?<![`\w])@([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)")

_DEFAULT_REFERRAL_BLOCKLIST = {
    'owasp-blt', 'openai', 'anthropic', 'claude',
    'google', 'microsoft', 'github', 'github-actions[bot]',
    'dependabot[bot]', 'coderabbitai[bot]', 'owasp-blt[bot]',
    'copilot[bot]', 'sentry[bot]',
}

_user_cache: dict = {}
_MAX = 1000  # simple FIFO cap


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_mentions(body: str) -> list:
    """Return a deduplicated list of @-mentioned GitHub usernames from *body*.

    Mentions immediately preceded by a backtick or word character are excluded
    by the regex lookbehind, but this does not robustly skip all usernames
    that appear inside inline or fenced code spans.
    """
    return list(dict.fromkeys(m.lower() for m in _MENTION_RE.findall(body)))


async def _github_user(login: str, token: str) -> Optional[dict]:
    key = (login or "").strip().lower()
    if not key:
        return None

    if key in _user_cache:
        return _user_cache[key]

    resp = await github_api("GET", f"/users/{key}", token)
    if resp.status != 200:
        return None  # don't cache failures

    data = json.loads(await resp.text() or "{}")
    if len(_user_cache) >= _MAX:  # simple FIFO eviction
        _user_cache.pop(next(iter(_user_cache)))
    _user_cache[key] = data
    return data


async def _is_valid_human_referree(
    login: str, token: str, block: set = _DEFAULT_REFERRAL_BLOCKLIST
) -> bool:
    """Return True only for real human GitHub users (not orgs/teams/bots/service accts)."""
    login_lower = (login or "").strip().lower()
    if not login_lower or '/' in login_lower:  # team mention like `@org/team`
        return False
    if login_lower.endswith('[bot]') or login_lower in block:
        return False
    user = await _github_user(login_lower, token)
    return bool(user) and (user.get('type', '').lower() == 'user')


async def _user_has_prior_activity(owner: str, username: str, token: str) -> bool:
    """Return True if *username* has any prior activity in the *owner* org.

    Checks (in order, stopping early):
    1. Issues or PRs authored by the user (search API).
    2. Comments on issues/PRs authored by the user (search API).

    Fails closed: a non-200 response is treated as "activity present" to
    prevent transient API errors from inflating referral counts.
    """
    base = f"org:{owner}+fork:false"
    u = username  # GitHub treats logins case-insensitively

    # 1) Authored issues/PRs anywhere in the org.
    authored_q = f"/search/issues?q={base}+author:{u}&per_page=1"
    resp = await github_api("GET", authored_q, token)
    if resp.status != 200:
        console.error(
            f"[Referral] Search API returned {resp.status} for {u} in {base}; "
            "treating as active to fail closed"
        )
        return True
    data = json.loads(await resp.text())
    if int(data.get("total_count") or 0) > 0:
        return True

    # 2) Comments authored anywhere in the org.
    commented_q = f"/search/issues?q={base}+commenter:{u}&per_page=1"
    resp2 = await github_api("GET", commented_q, token)
    if resp2.status != 200:
        console.error(
            f"[Referral] Search API returned {resp2.status} for {u} comments in {base}; "
            "treating as active to fail closed"
        )
        return True
    data2 = json.loads(await resp2.text())
    return int(data2.get("total_count") or 0) > 0


def _format_referral_rank_comment(
    referrer: str,
    total: int,
    leaderboard: list,
) -> str:
    """Build the congratulation comment body for a successful referral.

    Shows the referrer's rank along with 2 users above and 2 below in the
    monthly leaderboard.
    """
    rank = next(
        (i + 1 for i, (login, _) in enumerate(leaderboard) if login == referrer.lower()),
        len(leaderboard) + 1,
    )

    lines = [
        REFERRAL_MARKER,
        f":tada: @{referrer} You referred a new contributor! "
        f"Total referrals: **{total}**. Current rank: **#{rank}**.",
        "",
        "**Monthly Referral Leaderboard (your neighborhood)**",
        "",
        "| Rank | Contributor | Referrals |",
        "| ---: | :---------- | --------: |",
    ]

    start = max(0, rank - 3)
    end = min(len(leaderboard), rank + 2)
    for i in range(start, end):
        entry_login, entry_count = leaderboard[i]
        pos = i + 1
        marker = " ← you" if entry_login == referrer.lower() else ""
        lines.append(f"| {pos} | @{entry_login}{marker} | {entry_count} |")

    return "\n".join(lines)


async def _d1_record_referral(
    db, org: str, referrer: str, referred: str, repo: str, issue_number: int, month_key: str
) -> bool:
    """Record a referral in D1. Returns True if the row was newly inserted."""
    try:
        result = await db.prepare(
            """
            INSERT OR IGNORE INTO contributor_referrals
                (org, month_key, referrer_login, referred_login, repo, issue_number, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?, strftime('%s', 'now'))
            """
        ).bind(org, month_key, referrer.lower(), referred.lower(), repo, issue_number).run()
        return bool(getattr(result, "meta", {}).get("changes", 0) if hasattr(result, "meta") else result)
    except Exception as exc:
        console.error(f"[Referral] Failed to record referral {referrer}->{referred}: {exc}")
        return False


async def _d1_get_referral_count(db, org: str, referrer: str, month_key: str) -> int:
    """Return the total number of successful referrals made by *referrer* in *month_key*."""
    try:
        row = await _d1_first(
            db,
            """
            SELECT COUNT(*) AS cnt FROM contributor_referrals
            WHERE org = ? AND month_key = ? AND referrer_login = ?
            """,
            (org, month_key, referrer.lower()),
        )
        return int((row or {}).get("cnt") or 0)
    except Exception as exc:
        console.error(f"[Referral] Failed to get referral count for {referrer}: {exc}")
        return 0


async def _d1_get_referral_leaderboard(db, org: str, month_key: str) -> list:
    """Return list of (login, count) tuples sorted descending by referral count."""
    try:
        rows = await _d1_all(
            db,
            """
            SELECT referrer_login, COUNT(*) AS cnt
            FROM contributor_referrals
            WHERE org = ? AND month_key = ?
            GROUP BY referrer_login
            ORDER BY cnt DESC, referrer_login ASC
            """,
            (org, month_key),
        )
        return [(r["referrer_login"], int(r["cnt"])) for r in rows]
    except Exception as exc:
        console.error(f"[Referral] Failed to get leaderboard for {org}/{month_key}: {exc}")
        return []


async def _process_referral_mentions(
    owner: str,
    repo: str,
    issue_number: int,
    commenter: str,
    body: str,
    token: str,
    env,
) -> None:
    """Detect @-mentions of new contributors and record referrals in D1.

    For each mentioned username that has no prior activity in the repo, a
    referral is recorded and the commenter receives a congratulation comment.
    """
    import asyncio  # noqa: PLC0415 — imported late to avoid Pyodide compat issues

    db = _d1_binding(env)
    if not db:
        return

    mentions = _extract_mentions(body)
    if not mentions:
        return

    # Strip the commenter themselves from mentions.
    mentions = [m for m in mentions if m != commenter.lower()]
    if not mentions:
        return

    # Cap the number of mentions inspected per comment to avoid rate-limit bursts.
    if len(mentions) > MAX_REFERRAL_MENTIONS_PER_COMMENT:
        console.log(
            f"[Referral] Capping mentions from {len(mentions)} to "
            f"{MAX_REFERRAL_MENTIONS_PER_COMMENT} in {owner}/{repo}#{issue_number}"
        )
        mentions = mentions[:MAX_REFERRAL_MENTIONS_PER_COMMENT]

    # Keep only valid human users (not orgs/teams/bots/AI/service accounts)
    filtered = []
    for m in mentions:
        try:
            if await _is_valid_human_referree(m, token):
                filtered.append(m)
        except Exception:
            pass  # fail-closed: skip on error
    mentions = list(dict.fromkeys(filtered))
    if not mentions:
        return

    await _ensure_leaderboard_schema(db)
    mk = _month_key()
    new_referrals = []

    # Allow GitHub Search indexing to catch up before querying.
    await asyncio.sleep(5)

    for mentioned in mentions:
        try:
            already_active = await _user_has_prior_activity(owner, mentioned, token)
            if already_active:
                continue
            recorded = await _d1_record_referral(
                db, owner, commenter, mentioned, repo, issue_number, mk
            )
            if recorded:
                new_referrals.append(mentioned)
        except Exception as exc:
            console.error(f"[Referral] Error processing mention @{mentioned}: {exc}")

    if not new_referrals:
        return

    # Post one congrats comment covering all newly referred users.
    try:
        total = await _d1_get_referral_count(db, owner, commenter, mk)
        leaderboard = await _d1_get_referral_leaderboard(db, owner, mk)
        comment_body = _format_referral_rank_comment(commenter, total, leaderboard)
        await create_comment(owner, repo, issue_number, comment_body, token)
    except Exception as exc:
        console.error(f"[Referral] Failed to post congratulation comment: {exc}")
