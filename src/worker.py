"""BLT-Pool — Mentor Matching & GitHub Automation Platform.

A dual-purpose platform that:
1. Connects contributors with mentors through a shared mentor pool
2. Automates GitHub workflows (issue assignment, leaderboard, webhooks)

Homepage (/) displays the mentor grid with availability and assignments.
GitHub App documentation and installation at /github-app
(legacy alias: /github-app).

Entry point: ``on_fetch(request, env)`` — called by the Cloudflare runtime for
every incoming HTTP request.

Environment variables / secrets (configure via ``wrangler.toml`` or
``wrangler secret put``):
    APP_ID             — GitHub App numeric ID
    PRIVATE_KEY        — GitHub App RSA private key (PEM, PKCS#1 or PKCS#8)
    WEBHOOK_SECRET     — GitHub App webhook secret
    GITHUB_APP_SLUG    — GitHub App slug used to build the install URL
    BLT_API_URL        — BLT API base URL (default: https://blt-api.owasp-blt.workers.dev)
    GITHUB_CLIENT_ID   — OAuth client ID (optional)
    GITHUB_CLIENT_SECRET — OAuth client secret (optional)
"""

import base64
import calendar
import hashlib
import hmac
import json
import os
import re
import time
import traceback
from typing import Optional, Tuple
from urllib.parse import quote, urlparse
import asyncio

from js import Headers, Response, console, fetch  # Cloudflare Workers JS bindings

from core.db import _d1_binding
from models.mentor import _populate_mentors_table, _fetch_mentors_config, _load_mentors_from_d1
from models.assignment import _d1_get_active_assignments
from models.leaderboard import _ensure_leaderboard_schema, _fetch_leaderboard_data, _get_backfill_state, _run_incremental_backfill, _d1_get_user_comment_totals
from views.pages import _landing_html, _index_html, _webhook_security_status, _callback_html, _github_app_html, _secret_vars_status_html, _html, _json
from controllers.api import _handle_add_mentor
from controllers.webhook import handle_webhook
from controllers.mentor_commands import _check_stale_mentor_assignments
from services.admin import AdminService

# Re-exports required by existing test suites in test_worker.py
from core.crypto import _der_len, _wrap_pkcs1_as_pkcs8, pem_to_pkcs8_der, _b64url, verify_signature, create_github_jwt
from core.github_client import _gh_headers, github_api, get_installation_token, get_installation_access_token, create_comment, create_reaction, report_bug_to_blt, _is_human, _is_bot, _is_coderabbit_ping, _is_maintainer, _extract_command, _ensure_label_exists
from core.db import _month_key, _month_window, _d1_run, _to_py, _d1_all, _d1_first, _time_ago
from models.mentor import _parse_yaml_scalar, _parse_mentors_yaml, _fetch_mentors_config, _load_mentors_local, _fetch_mentor_stats_from_d1, _get_mentor_load_map, _select_mentor, _find_assigned_mentor_from_comments, _get_last_human_activity_ts, _is_security_issue, _d1_add_mentor, _NAME_RE, _GH_USERNAME_RE, _SPECIALTY_RE, _TIMEZONE_RE, MENTOR_ASSIGNED_LABEL, NEEDS_MENTOR_LABEL, MENTOR_LABEL_COLOR, MENTOR_MAX_MENTEES, SECURITY_BYPASS_LABELS, MENTOR_STALE_DAYS, _MENTOR_STATS_CACHE_TTL
from models.assignment import _d1_record_mentor_assignment, _d1_remove_mentor_assignment, _d1_get_mentor_loads, _d1_get_active_assignments
from models.leaderboard import _ensure_leaderboard_schema, _d1_get_user_comment_totals, _d1_inc_open_pr, _d1_inc_monthly, _track_pr_opened_in_d1, _track_pr_closed_in_d1, _track_pr_reopened_in_d1, _track_comment_in_d1, _track_review_in_d1, _calculate_leaderboard_stats_from_d1, _get_backfill_state, _set_backfill_state, _run_incremental_backfill, _backfill_repo_month_if_needed, _reset_leaderboard_month, _fetch_org_repos, _calculate_leaderboard_stats, _fetch_leaderboard_data
from views.comments import _parse_github_timestamp, _avatar_img_tag, _format_leaderboard_comment, _format_reviewer_leaderboard_comment, _post_reviewer_leaderboard, _post_or_update_leaderboard, _check_and_close_excess_prs, _check_rank_improvement, LEADERBOARD_MARKER, REVIEWER_LEADERBOARD_MARKER, MERGED_PR_COMMENT_MARKER
from views.pages import _CALLBACK_HTML, _generate_mentor_row, _build_referral_leaderboard
from controllers.issue_handlers import handle_issue_comment, _assign, _unassign, _approve, _deny, _NO_WELCOME_REPOS_YML_PATH, _NO_WELCOME_REPOS_CACHE, _load_no_welcome_repos, handle_issue_opened, handle_issue_labeled, ASSIGN_COMMAND, UNASSIGN_COMMAND, APPROVE_COMMAND, DENY_COMMAND, LEADERBOARD_COMMAND, MENTOR_COMMAND, UNMENTOR_COMMAND, MENTOR_PAUSE_COMMAND, HANDOFF_COMMAND, REMATCH_COMMAND, MAX_ASSIGNEES, ASSIGNMENT_DURATION_HOURS, BUG_LABELS, HELP_WANTED_LABEL, TRIAGE_REVIEWER, NEEDS_APPROVAL_LABEL, NEEDS_APPROVAL_LABEL_COLOR
from controllers.pr_handlers import handle_pull_request_opened, _request_mentor_reviewer_for_pr, _assign_round_robin_mentor_reviewer, _post_merged_pr_combined_comment, handle_pull_request_closed, handle_pull_request_review_submitted, label_pending_checks, check_workflows_awaiting_approval, _try_label_pending_checks, handle_workflow_run, handle_check_run, MENTOR_AUTO_PR_REVIEWER_ENABLED, UNRESOLVED_CONVERSATIONS_CHECK_NAME, UNRESOLVED_CONVERSATIONS_MARKER
from controllers.mentor_commands import _assign_mentor_to_issue, handle_mentor_command, handle_mentor_unassign, handle_mentor_pause, handle_mentor_handoff, handle_mentor_rematch
from controllers.peer_review import _is_excluded_reviewer, get_valid_reviewers, ensure_label_exists, update_peer_review_labels, check_peer_review_and_comment, handle_pull_request_review, handle_pull_request_for_review
from controllers.api import _verify_gh_user_exists, _handle_admin_reset
from services.mentor_seed import INITIAL_MENTORS
from checks_api import build_update_check_run_payloads
from controllers.referral import (
    _extract_mentions, _user_has_prior_activity, _is_valid_human_referree,
    _format_referral_rank_comment, _process_referral_mentions,
    MAX_REFERRAL_MENTIONS_PER_COMMENT, REFERRAL_MARKER,
    _d1_record_referral, _d1_get_referral_count, _d1_get_referral_leaderboard,
)
_INITIAL_MENTORS = INITIAL_MENTORS

def _admin_path(env) -> str:
    return getattr(env, "ADMIN_PATH", "/admin")


async def _get_last_assign_requester(
    owner: str, repo: str, num: int, token: str
) -> Optional[str]:
    """Return the login of the last human who commented ``/assign`` on the issue, or None."""
    try:
        page = 1
        per_page = 100
        while True:
            resp = await github_api(
                "GET",
                f"/repos/{owner}/{repo}/issues/{num}/comments"
                f"?per_page={per_page}&page={page}&sort=created&direction=desc",
                token,
            )
            if resp.status != 200:
                return None
            comments = json.loads(await resp.text())
            if not comments:
                break
            for c in comments:
                user = c.get("user") or {}
                body = (c.get("body") or "").strip()
                login = user.get("login", "")
                if not login or not _is_human(user):
                    continue
                if _extract_command(body) == ASSIGN_COMMAND:
                    return login
            if len(comments) < per_page:
                break
            page += 1
    except Exception:
        pass
    return None


async def _approve(
    owner: str, repo: str, issue: dict, login: str, token: str
) -> None:
    """Handle the ``/approve`` command.

    Only TRIAGE_REVIEWER is authorised. Prefers the last /assign requester as
    the assignee; falls back to the issue opener if no prior request exists.
    """
    from controllers.issue_handlers import (  # noqa: PLC0415
        TRIAGE_REVIEWER, HELP_WANTED_LABEL, MAX_ASSIGNEES, NEEDS_APPROVAL_LABEL
    )
    num = issue["number"]
    if login.lower() != TRIAGE_REVIEWER.lower():
        await create_comment(
            owner, repo, num,
            f"@{login} Only @{TRIAGE_REVIEWER} can approve issues.",
            token,
        )
        return
    if issue.get("pull_request") or issue.get("state") == "closed":
        return
    await github_api(
        "POST",
        f"/repos/{owner}/{repo}/issues/{num}/labels",
        token,
        {"labels": [HELP_WANTED_LABEL]},
    )
    last_requester = await _get_last_assign_requester(owner, repo, num, token)
    assignee = last_requester or (issue.get("user") or {}).get("login", "")
    opener_assigned = False
    assignment_note = ""
    if assignee:
        assignees = issue.get("assignees") or []
        assignee_logins = {
            a.get("login")
            for a in assignees
            if isinstance(a, dict) and a.get("login")
        }
        if assignee in assignee_logins:
            opener_assigned = True
        elif len(assignee_logins) >= MAX_ASSIGNEES:
            assignment_note = (
                "However, this issue already has the maximum number of assignees, "
                "so the opener was not additionally assigned."
            )
        elif assignee_logins:
            assignment_note = (
                "Note: this issue already has an assignee, so the opener was not "
                "automatically assigned."
            )
        else:
            await github_api(
                "POST",
                f"/repos/{owner}/{repo}/issues/{num}/assignees",
                token,
                {"assignees": [assignee]},
            )
            opener_assigned = True
    if assignee and opener_assigned:
        assignment_text = f"@{assignee} You have been assigned — good luck! 🚀\n\n"
    elif assignment_note:
        assignment_text = assignment_note + "\n\n"
    else:
        assignment_text = ""
    await create_comment(
        owner, repo, num,
        f"✅ This issue has been approved by @{login}!\n\n"
        + assignment_text
        + f'The `"{HELP_WANTED_LABEL}"` label has been added so others can also use '
        f"`/assign` to claim this issue.",
        token,
    )


async def _user_has_prior_activity(owner: str, username: str, token: str) -> bool:
    """Return True if *username* has any prior activity in the *owner* org.

    Fails closed: non-200 responses are treated as "activity present" to
    prevent transient API errors from inflating referral counts.
    """
    base = f"org:{owner}+fork:false"
    u = username

    # 1) Authored issues/PRs
    resp = await github_api("GET", f"/search/issues?q={base}+author:{u}&per_page=1", token)
    if resp.status != 200:
        console.error(
            f"[Referral] Search API returned {resp.status} for {u} in {base}; "
            "treating as active to fail closed"
        )
        return True
    data = json.loads(await resp.text())
    if int(data.get("total_count") or 0) > 0:
        return True

    # 2) Comments anywhere in the org
    resp2 = await github_api("GET", f"/search/issues?q={base}+commenter:{u}&per_page=1", token)
    if resp2.status != 200:
        return True
    data2 = json.loads(await resp2.text())
    return int(data2.get("total_count") or 0) > 0


async def _process_referral_mentions(
    owner: str,
    repo: str,
    issue_number: int,
    commenter: str,
    body: str,
    token: str,
    env,
) -> None:
    """Detect @-mentions of new contributors and record referrals in D1."""
    import asyncio as _asyncio  # noqa: PLC0415

    db = _d1_binding(env)
    if not db:
        return

    mentions = _extract_mentions(body)
    if not mentions:
        return

    mentions = [m for m in mentions if m != commenter.lower()]
    if not mentions:
        return

    if len(mentions) > MAX_REFERRAL_MENTIONS_PER_COMMENT:
        mentions = mentions[:MAX_REFERRAL_MENTIONS_PER_COMMENT]

    filtered = []
    for m in mentions:
        try:
            if await _is_valid_human_referree(m, token):
                filtered.append(m)
        except Exception:
            pass
    mentions = list(dict.fromkeys(filtered))
    if not mentions:
        return

    await _ensure_leaderboard_schema(db)
    mk = _month_key()
    new_referrals = []

    await _asyncio.sleep(5)

    for mentioned in mentions:
        try:
            already_active = await _user_has_prior_activity(owner, mentioned, token)
            if already_active:
                continue
            recorded = await _d1_record_referral(db, owner, commenter, mentioned, repo, issue_number, mk)
            if recorded:
                new_referrals.append(mentioned)
        except Exception as exc:
            console.error(f"[Referral] Error processing mention @{mentioned}: {exc}")

    if not new_referrals:
        return

    try:
        total = await _d1_get_referral_count(db, owner, commenter, mk)
        leaderboard = await _d1_get_referral_leaderboard(db, owner, mk)
        comment_body = _format_referral_rank_comment(commenter, total, leaderboard)
        await create_comment(owner, repo, issue_number, comment_body, token)
    except Exception as exc:
        console.error(f"[Referral] Failed to post congratulation comment: {exc}")


async def handle_issue_comment(payload: dict, token: str, env=None, ctx=None) -> None:
    """Issue comment handler — extends issue_handlers version with ctx/referral support.

    When ``ctx`` (Cloudflare ExecutionContext) is provided, the referral
    processing is deferred via ``ctx.waitUntil()`` so it doesn't block the
    webhook response.  When ``ctx=None`` (unit tests / non-Workers environments)
    it is awaited inline.
    """
    from controllers.issue_handlers import handle_issue_comment as _base_handle_issue_comment  # noqa: PLC0415
    from controllers.issue_handlers import _is_human as _is_human_check  # noqa: PLC0415

    # Delegate the core command handling to the controller.
    await _base_handle_issue_comment(payload, token, env=env)

    # Trigger referral processing for human comments.
    comment = payload.get("comment") or {}
    issue = payload.get("issue") or {}
    if not _is_human(comment.get("user") or {}):
        return
    body = (comment.get("body") or "").strip()
    owner = (payload.get("repository") or {}).get("owner", {}).get("login", "")
    repo = (payload.get("repository") or {}).get("name", "")
    issue_number = issue.get("number")
    commenter = (comment.get("user") or {}).get("login", "")
    if not (owner and repo and issue_number and commenter and body):
        return

    coro = _process_referral_mentions(owner, repo, issue_number, commenter, body, token, env)
    if ctx is not None:
        ctx.waitUntil(coro)
    else:
        await coro


async def check_unresolved_conversations(payload, token):
    """Add label, create a check run, and post a comment if PR has unresolved review conversations."""
    pr = payload.get("pull_request")
    if not pr:
        return

    owner = payload["repository"]["owner"]["login"]
    repo = payload["repository"]["name"]
    number = pr["number"]
    head_sha = pr.get("head", {}).get("sha", "")

    query = """
    query($owner: String!, $repo: String!, $number: Int!) {
      repository(owner: $owner, name: $repo) {
        pullRequest(number: $number) {
          reviewThreads(first: 100) {
            nodes {
              isResolved
            }
          }
        }
      }
    }
    """

    resp = await fetch(
        "https://api.github.com/graphql",
        method="POST",
        headers=_gh_headers(token),
        body=json.dumps({
            "query": query,
            "variables": {"owner": owner, "repo": repo, "number": number},
        }),
    )

    if resp.status != 200:
        console.error(f"[BLT] GraphQL query failed: {resp.status}")
        return

    result = json.loads(await resp.text())
    pull_request = (
        result.get("data", {})
        .get("repository", {})
        .get("pullRequest")
    )
    if result.get("errors") or pull_request is None:
        console.error(f"[BLT] GraphQL reviewThreads query returned errors: {result.get('errors')}")
        return
    threads = (
        pull_request
        .get("reviewThreads", {})
        .get("nodes", [])
    )

    unresolved = any(not t.get("isResolved", True) for t in threads)

    unresolved_count = sum(not t.get("isResolved", True) for t in threads)

    # Remove any existing unresolved-conversations labels
    from urllib.parse import quote  # noqa: PLC0415
    from controllers.pr_handlers import _ensure_label_exists  # noqa: PLC0415
    resp_labels = await github_api(
        "GET",
        f"/repos/{owner}/{repo}/issues/{number}/labels",
        token,
    )
    if resp_labels.status == 200:
        current_labels = json.loads(await resp_labels.text())
        for lb in current_labels:
            if lb["name"].startswith("unresolved-conversations"):
                await github_api(
                    "DELETE",
                    f"/repos/{owner}/{repo}/issues/{number}/labels/{quote(lb['name'], safe='')}",
                    token,
                )

    label = f"unresolved-conversations: {unresolved_count}"

    if unresolved:
        await _ensure_label_exists(owner, repo, label, "e74c3c", token)  # Red
    else:
        await _ensure_label_exists(owner, repo, label, "5cb85c", token)  # Green

    await github_api(
        "POST",
        f"/repos/{owner}/{repo}/issues/{number}/labels",
        token,
        {"labels": [label]},
    )

    # Create or update a check run that fails when there are unresolved conversations.
    noun = "conversation" if unresolved_count == 1 else "conversations"
    if head_sha:
        if unresolved:
            check_title = f"{unresolved_count} unresolved {noun}"
            check_summary = (
                f"There {'is' if unresolved_count == 1 else 'are'} {unresolved_count} "
                f"unresolved review {noun} that must be resolved before merging."
            )
            check_conclusion = "failure"
        else:
            check_title = "All conversations resolved"
            check_summary = "All review conversations have been resolved."
            check_conclusion = "success"

        update_payload = build_update_check_run_payloads(
            status="completed",
            title=check_title,
            summary=check_summary,
            conclusion=check_conclusion,
        )[0]

        # Reuse an existing check run for this SHA/name to avoid creating
        # multiple redundant check runs when called from different event types.
        existing_check_run_id = None
        resp_check_runs = await github_api(
            "GET",
            f"/repos/{owner}/{repo}/commits/{head_sha}/check-runs",
            token,
        )
        if resp_check_runs.status == 200:
            resp_data = json.loads(await resp_check_runs.text())
            for check_run in resp_data.get("check_runs", []):
                if check_run.get("name") == UNRESOLVED_CONVERSATIONS_CHECK_NAME:
                    existing_check_run_id = check_run.get("id")
                    break

        if existing_check_run_id is not None:
            await github_api(
                "PATCH",
                f"/repos/{owner}/{repo}/check-runs/{existing_check_run_id}",
                token,
                update_payload,
            )
        else:
            await github_api(
                "POST",
                f"/repos/{owner}/{repo}/check-runs",
                token,
                {"name": UNRESOLVED_CONVERSATIONS_CHECK_NAME, "head_sha": head_sha, **update_payload},
            )

    # Post or update a comment when there are unresolved conversations; remove
    # it once all conversations are resolved.
    marker = UNRESOLVED_CONVERSATIONS_MARKER
    existing_comment_id = None
    page = 1
    while True:
        resp_comments = await github_api(
            "GET",
            f"/repos/{owner}/{repo}/issues/{number}/comments?per_page=100&page={page}",
            token,
        )
        if resp_comments.status != 200:
            break
        comments = json.loads(await resp_comments.text())
        if not comments:
            break
        for comment in comments:
            if marker in comment.get("body", ""):
                existing_comment_id = comment["id"]
                break
        if existing_comment_id is not None:
            break
        page += 1

    if unresolved:
        pr_author_login = (pr.get("user") or {}).get("login", "")
        username_block = f"@{pr_author_login}\n\n" if pr_author_login else ""
        comment_body = (
            f"{marker}\n"
            f"{username_block}⚠️ This pull request has **{unresolved_count} unresolved review "
            f"{noun}** that must be resolved before merging."
        )
        if existing_comment_id is not None:
            await github_api(
                "PATCH",
                f"/repos/{owner}/{repo}/issues/comments/{existing_comment_id}",
                token,
                {"body": comment_body},
            )
        else:
            await create_comment(owner, repo, number, comment_body, token)
    elif existing_comment_id is not None:
        # All conversations resolved — remove the warning comment.
        await github_api(
            "DELETE",
            f"/repos/{owner}/{repo}/issues/comments/{existing_comment_id}",
            token,
        )


# Cloudflare Workers entry point
async def on_fetch(request, env) -> Response:
    """Main routing entry point for incoming HTTP requests."""
    url = str(request.url)
    method = request.method
    path = "/" + "/".join(url.split("//", 1)[-1].split("/")[1:]).split("?")[0]

    if request.method == "OPTIONS":
        cors_headers = Headers.new([
            ["Access-Control-Allow-Origin", "*"],
            ["Access-Control-Allow-Methods", "GET, POST, OPTIONS"],
            ["Access-Control-Allow-Headers", "Content-Type"]
        ])
        return Response.new("", headers=cors_headers, status=204)

    if path == "/logo-sm.png" or path.endswith("logo-sm.png"):
        return await env.ASSETS.fetch(request)

    admin_response = await AdminService(env).handle(request)
    if admin_response is not None:
        return admin_response

    if method == "GET" and path == "/":
        # Load mentors from D1.
        org = getattr(env, "GITHUB_ORG", "OWASP-BLT")
        mentors: list = []
        try:
            mentors = await _load_mentors_local(env)
        except Exception as exc:
            console.error(f"[MentorPool] Failed to load mentors for homepage: {exc}")
        # Fetch per-mentor activity stats from D1 (best-effort; no stats if D1 unavailable).
        mentor_stats: dict = {}
        try:
            token = getattr(env, "GITHUB_TOKEN", "")
            mentor_stats = await _fetch_mentor_stats_from_d1(env, org, mentors=mentors, token=token)
        except Exception as exc:
            console.error(f"[MentorPool] Failed to fetch mentor stats for homepage: {exc}")
        # Fetch active mentor assignments from D1 (best-effort).
        active_assignments: list = []
        assignment_comment_stats: dict = {}
        db = _d1_binding(env)
        if db:
            try:
                await _ensure_leaderboard_schema(db)
                active_assignments = await _d1_get_active_assignments(db, org)
            except Exception as exc:
                console.error(f"[MentorPool] Failed to fetch active assignments for homepage: {exc}")
            if active_assignments:
                try:
                    all_logins = list({
                        login
                        for a in active_assignments
                        for login in (a["mentor_login"], a.get("mentee_login", ""))
                        if login
                    })
                    assignment_comment_stats = await _d1_get_user_comment_totals(db, org, all_logins)
                except Exception as exc:
                    console.error(f"[MentorPool] Failed to fetch assignment comment stats: {exc}")
        return _html(_index_html(mentors, mentor_stats, active_assignments, assignment_comment_stats, _admin_path(env)))

    if method == "GET" and path == "/github-app":
        app_slug = getattr(env, "GITHUB_APP_SLUG", "")
        return _html(_github_app_html(app_slug, env, admin_path=_admin_path(env)))

    if method == "GET" and path == "/health":
        webhook_security = _webhook_security_status(env)
        return _json(
            {
                "status": "ok" if webhook_security["ready"] else "degraded",
                "service": "BLT-Pool",
                "checks": {
                    "webhook_security": webhook_security,
                },
            },
            allow_cors=True,
        )

    if method == "POST" and path == "/api/mentors":
        return await _handle_add_mentor(request, env)

    if method == "POST" and path == "/api/github/webhooks":
        return await handle_webhook(request, env)

    # GitHub redirects here after a successful installation
    if method == "GET" and path == "/callback":
        return _html(_callback_html())

    # Admin: reset corrupted leaderboard data for a given org/month so a fresh
    # backfill can re-populate it.  Requires ADMIN_SECRET env variable.
    if method == "POST" and path in {"/admin/reset-leaderboard-month", f"{_admin_path(env)}/reset-leaderboard-month"}:
        admin_secret = getattr(env, "ADMIN_SECRET", "")
        if not admin_secret:
            return _json({"error": "Admin endpoint not configured"}, 403)
        auth_header = (request.headers.get("Authorization") or "").strip()
        if auth_header != f"Bearer {admin_secret}":
            return _json({"error": "Unauthorized"}, 401)
        try:
            body = json.loads(await request.text())
        except Exception:
            return _json({"error": "Invalid JSON body"}, 400)
        org = (body.get("org") or "").strip()
        if not org:
            return _json({"error": "Missing required field: org"}, 400)
        month_key = (body.get("month_key") or "").strip()
        if not month_key:
            return _json(
                {"error": "Missing required field: month_key (e.g. '2026-03'). "
                 "Provide an explicit month to prevent accidental resets."},
                400,
            )
        if not re.fullmatch(r"\d{4}-\d{2}", month_key):
            return _json({"error": "month_key must be in YYYY-MM format (e.g. '2026-03')"}, 400)
        db = _d1_binding(env)
        if not db:
            return _json({"error": "No D1 binding available"}, 500)
        deleted = await _reset_leaderboard_month(org, month_key, db)
        return _json({"ok": True, "org": org, "month_key": month_key, "tables_cleared": deleted})

    return _json({"error": "Not found"}, 404)


# ---------------------------------------------------------------------------
# Scheduled event handler — runs on cron triggers
# ---------------------------------------------------------------------------


async def _run_scheduled(env):
    """Handle scheduled cron events to check and unassign stale issues.
    
    This runs periodically (configured in wrangler.toml) to find issues that:
    - Have assignees
    - Were assigned more than ASSIGNMENT_DURATION_HOURS ago
    - Have no linked pull requests
    
    Such issues are automatically unassigned to free them up for other contributors.
    """
    console.log("[CRON] Starting stale assignment check...")

    try:
        # 1. GitHub App Webhook endpoint
        if url.endswith("/webhook") and request.method == "POST":
            return await handle_webhook(request, env)

        # 2. Mentor matching pool directory (Homepage)
        if url.endswith("/") and request.method == "GET":
            from core.db import _d1_binding
            db = _d1_binding(env)
            if db:
                await _ensure_leaderboard_schema(db)
                from models.mentor import _populate_mentors_table
                await _populate_mentors_table(db)
            
            # Fetch mentors, passing True to trigger D1 population if needed
            mentors = await _fetch_mentors_config(env=env)
            from models.leaderboard import _calculate_leaderboard_stats_from_d1
            stats = await _calculate_leaderboard_stats_from_d1("OWASP", env) or {}
            active_assignments = await _d1_get_active_assignments(db, "OWASP") if db else []
            
            mentor_logins = [m.get("github_username") for m in mentors if m.get("github_username")]
            mentee_logins = [a.get("mentee_login") for a in active_assignments if a.get("mentee_login")]
            comment_stats = await _d1_get_user_comment_totals(db, "OWASP", mentor_logins + mentee_logins) if db else {}

            return _html(
                _index_html(
                    mentors=mentors,
                    mentor_stats=stats,
                    active_assignments=active_assignments,
                    assignment_comment_stats=comment_stats,
                    admin_path=_admin_path(env),
                )
            )

        # 3. GitHub App documentation & install link
        if (url.endswith("/github-app") or url.endswith("/github-app/")) and request.method == "GET":
            slug = getattr(env, "GITHUB_APP_SLUG", "blt-github-app")
            return _html(_github_app_html(slug, env, admin_path=_admin_path(env)))

        # 4. GitHub callback (redirects back to homepage after app installation)
        if url.split("?")[0].endswith("/callback") and request.method == "GET":
            return _html(_callback_html())

        # 5. REST API: Add new mentor (called from client-side JS on the homepage form)
        if url.endswith("/api/mentors") and request.method == "POST":
            return await _handle_add_mentor(request, env)
            
        if url.endswith("/api/github/webhooks") and request.method == "POST":
            from controllers.webhook import handle_webhook
            return await handle_webhook(request, env)
            
        if url.endswith("/admin/reset-leaderboard-month") and request.method == "POST":
            return await _handle_admin_reset(request, env)
            
        if url.endswith("/health") and request.method == "GET":
            from views.pages import _webhook_security_status
            return _json(_webhook_security_status(env))

        # Admin Service Integration
        if "/admin" in url:
            return await AdminService(env).handle(request)

        return _json({"error": "Not found"}, 404)
    except Exception as exc:
        traceback.print_exc()
        console.error(f"[BLT] Setup/routing error: {exc}")
        return _json({"error": "Internal server error"}, 500)

# ---------------------------------------------------------------------------
# Cloudflare Workers Cron Trigger
# ---------------------------------------------------------------------------

async def on_scheduled(controller, env, ctx=None):
    """Entry point for Cloudflare Scheduled (Cron) events.

    Triggers background jobs that cannot rely on webhooks, such as
    backfilling historical leaderboard stats and releasing stale mentors.
    """
    console.log("[BLT][Timer] Triggered scheduled background task")
    try:
        await _run_scheduled(env)
    except Exception as e:
        console.error(f"[BLT][Timer] Uncaught error: {e}")

# Provide both entry point names just in case the JS shim expects a specific one.
scheduled = on_scheduled


async def _run_scheduled(env) -> None:
    """Run all scheduled background tasks."""
    from core.db import _d1_binding, _month_key
    installation_id = "56316277"  # Default OWASP installation
    app_id = getattr(env, "APP_ID", "")
    private_key = getattr(env, "PRIVATE_KEY", "")
    owner = "OWASP-BLT"
    
    db = _d1_binding(env)
    
    # 1. Backfill stats
    if db and app_id and private_key:
        month_key = _month_key()
        state = await _get_backfill_state(db, owner, month_key)
        if not state["completed"]:
            token = await get_installation_token(installation_id, app_id, private_key)
            if not token:
                console.error("[Leaderboard] Cannot run backfill: failed to get token")
            else:
                await _run_incremental_backfill(owner, token, env)
        
    # 2. Free stale mentor assignments
    if app_id and private_key:
        token = await get_installation_token(installation_id, app_id, private_key)
        if token:
            # Check a few core repositories (this could be expanded or made dynamic)
            for repo in ["owasp.github.io", "BLT", "blt-extension"]:
                await _check_stale_mentor_assignments("OWASP", repo, token, env=env)
