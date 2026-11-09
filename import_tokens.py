"""Import a raw JWT list (jwt_token.json) into the token file app.py loads.

Your tool gives tokens without a uid or host; this reads them back out of the
JWT payload (external_uid, exp, lock_region) and writes token_<server>.json in
the exact shape load_tokens_from_file() expects.

Usage:
    python import_tokens.py jwt_token.json
    python import_tokens.py jwt_token.json --server SG --login-url https://client.sg.example.com
"""
import argparse
import json
import os
from datetime import datetime, timezone

import jwt

TOKEN_FILES = {
    "IND": "token_ind.json", "BR": "token_br.json", "BD": "token_bd.json",
    "RU": "token_ru.json", "SG": "token_sg.json",
}


def read_tokens(path):
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, dict):
        items = list((data.get("tokens") or {}).values())
        if not items and data.get("token"):
            items = [data]
    else:
        items = data
    out = []
    for it in items:
        if isinstance(it, str):
            out.append({"token": it})
        elif isinstance(it, dict) and it.get("token"):
            out.append(it)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("source", nargs="?", default="jwt_token.json")
    ap.add_argument("--server", default="SG")
    ap.add_argument("--login-url", default=None,
                    help="API base URL for this region (from the token service's Login_url)")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    server = args.server.upper()
    target = args.out or TOKEN_FILES.get(server, f"token_{server.lower()}.json")

    raw = read_tokens(args.source)
    now = datetime.now(timezone.utc)
    tokens = {}
    expired = bad = 0

    for it in raw:
        tok = it["token"]
        try:
            p = jwt.decode(tok, options={"verify_signature": False})
        except Exception:
            bad += 1
            continue
        uid = p.get("external_uid") or p.get("account_id")
        exp = p.get("exp")
        if not uid or not exp:
            bad += 1
            continue
        expires_at = datetime.fromtimestamp(int(exp), tz=timezone.utc)
        if expires_at <= now:
            expired += 1
            continue
        tokens[str(uid)] = {
            "token": tok,
            "expires_at": expires_at.isoformat(),
            "login_url": it.get("login_url") or args.login_url,
            "region": (p.get("lock_region") or p.get("noti_region") or server).upper(),
            "fetched_at": it.get("fetched_at") or now.timestamp(),
        }

    # keep tokens already in the target file that this run did not touch
    if os.path.exists(target):
        try:
            with open(target) as f:
                old = json.load(f)
            for uid, c in (old.get("tokens") or {}).items():
                tc = json.loads(json.dumps(c))
                if uid not in tokens:
                    try:
                        if datetime.fromisoformat(tc["expires_at"]) > now:
                            tokens[uid] = tc
                    except Exception:
                        pass
        except Exception:
            pass

    data = {
        "server": server,
        "updated_at": now.isoformat(),
        "total": len(tokens),
        "tokens": tokens,
    }
    with open(target, "w") as f:
        json.dump(data, f, indent=2)

    print(f"read {len(raw)} tokens from {args.source}")
    print(f"wrote {len(tokens)} valid tokens -> {target} (expired {expired}, unreadable {bad})")
    if tokens and not args.login_url and not any(c.get("login_url") for c in tokens.values()):
        print("WARNING: no login_url set — app.py will fall back to URLS[server],"
              " which is wrong for SG. Re-run with --login-url <api base url>.")
    if tokens:
        first = min(tokens.items(), key=lambda kv: kv[1]["expires_at"])
        print(f"soonest expiry: {first[1]['expires_at']} (uid {first[0]})")


if __name__ == "__main__":
    main()
