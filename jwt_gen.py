"""Local Free Fire JWT generator (guest OAuth -> MajorLogin).

Based on the token-service script, updated to the current login flow:

  OAuth guest grant  ->  access_token + open_id
  MajorLogin (LoginReq protobuf)  ->  token, lock_region, server_url

`server_url` is the important one: it is the per-region API base the game
itself uses, which is what the like endpoint needs.

    python jwt_gen.py <uid> <password>
    FF_MAJOR_LOGIN_URL=https://loginbp.example.com/MajorLogin python jwt_gen.py ...

Env overrides: FF_OAUTH_URL, FF_MAJOR_LOGIN_URL, FF_RELEASE_VERSION,
FF_LOGIN_URL_<REGION>.
"""
import base64
import json
import os
import re
import time

import requests
import urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

OAUTH_URL = os.environ.get(
    "FF_OAUTH_URL", "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant")

# Rotating login hosts — the first one that answers wins.
MAJOR_LOGIN_HOSTS = [
    h for h in [
        os.environ.get("FF_MAJOR_LOGIN_URL"),
        "https://loginbp.ggblueshark.com/MajorLogin",
        "https://loginbp.ppmainecoonghj.com/MajorLogin",
    ] if h
]

RELEASE_VERSION = os.environ.get("FF_RELEASE_VERSION", "OB55")
X_UNITY_VERSION = "2018.4.11f1"
X_GA_SV = os.environ.get("FF_X_GA_SV", "1789556611")
MAJOR_LOGIN_UA = "Dalvik/2.1.0 (Linux; U; Android 15; I2404 Build/AP3A.240905.015.A2_V000L1)"

REGION_MAP = {
    "IN": "IND", "INDIA": "IND", "BRAZIL": "BR", "SINGAPORE": "SG",
    "INDONESIA": "ID", "THAILAND": "TH", "VIETNAM": "VN", "MENA": "ME",
    "PAKISTAN": "PK", "BANGLADESH": "BD", "MALAYSIA": "MY",
    "PHILIPPINES": "PH", "RUSSIA": "RU", "MEXICO": "MX", "USA": "US",
    "UNITED STATES": "US", "EUROPE": "EU", "EGYPT": "EG", "SAUDI": "SA",
    "SAUDI ARABIA": "SA", "TURKEY": "TR", "TAIWAN": "TW", "KOREA": "KR",
    "SOUTH KOREA": "KR", "JAPAN": "JP", "COLOMBIA": "CO", "ARGENTINA": "AR",
    "CHILE": "CL", "PERU": "PE",
}

# Region -> client API host. FF_LOGIN_URL_<REGION> wins; server_url from the
# login response wins over both.
REGION_URL = {
    "IND": "client.ind.freefiremobile.com",
    "BR": "client.us.freefiremobile.com",
    "US": "client.us.freefiremobile.com",
    "SAC": "client.us.freefiremobile.com",
    "NA": "client.us.freefiremobile.com",
    # SG/SEA tokens are accepted by this shard (see README); the authoritative
    # value is server_url from MajorLogin.
    "SG": "clientbp.ppmainecoonghj.com",
    "ID": "client.id.freefiremobile.com",
    "TH": "client.th.freefiremobile.com",
    "VN": "client.vn.freefiremobile.com",
    "ME": "client.me.freefiremobile.com",
    "PK": "client.pk.freefiremobile.com",
    "BD": "clientbp.ppmainecoonghj.com",
    "MY": "client.my.freefiremobile.com",
    "PH": "client.ph.freefiremobile.com",
    "RU": "client.ru.freefiremobile.com",
    "EU": "client.eu.freefiremobile.com",
    "TW": "client.tw.freefiremobile.com",
}


# --------------------------------------------------------------------------
# protobuf (built at runtime: no giant generated blobs to keep in sync)
# --------------------------------------------------------------------------
_F = descriptor_pb2.FieldDescriptorProto
_PROTO_PACKAGE = "fflogin"

_LOGIN_RES_FIELDS = [
    ("account_id", 1, _F.TYPE_UINT64, _F.LABEL_OPTIONAL),
    ("lock_region", 2, _F.TYPE_STRING, _F.LABEL_OPTIONAL),
    ("noti_region", 3, _F.TYPE_STRING, _F.LABEL_OPTIONAL),
    ("ip_region", 4, _F.TYPE_STRING, _F.LABEL_OPTIONAL),
    ("agora_environment", 5, _F.TYPE_STRING, _F.LABEL_OPTIONAL),
    ("new_active_region", 6, _F.TYPE_STRING, _F.LABEL_OPTIONAL),
    ("recommend_regions", 7, _F.TYPE_STRING, _F.LABEL_REPEATED),
    ("token", 8, _F.TYPE_STRING, _F.LABEL_OPTIONAL),
    ("ttl", 9, _F.TYPE_UINT32, _F.LABEL_OPTIONAL),
    ("server_url", 10, _F.TYPE_STRING, _F.LABEL_OPTIONAL),
    ("emulator_score", 11, _F.TYPE_UINT32, _F.LABEL_OPTIONAL),
    ("tp_url", 14, _F.TYPE_STRING, _F.LABEL_OPTIONAL),
    ("app_server_id", 15, _F.TYPE_UINT32, _F.LABEL_OPTIONAL),
    ("ano_url", 16, _F.TYPE_STRING, _F.LABEL_OPTIONAL),
    ("ip_city", 17, _F.TYPE_STRING, _F.LABEL_OPTIONAL),
    ("ip_subdivision", 18, _F.TYPE_STRING, _F.LABEL_OPTIONAL),
]


def _build_messages():
    pool = descriptor_pool.Default()
    try:
        pool.FindMessageTypeByName(f"{_PROTO_PACKAGE}.LoginReq")
        exists = True
    except KeyError:
        exists = False
    if not exists:
        fd = descriptor_pb2.FileDescriptorProto()
        fd.name = "ff_login.proto"
        fd.package = _PROTO_PACKAGE
        fd.syntax = "proto3"

        req = fd.message_type.add()
        req.name = "LoginReq"
        for name, number in [("open_id", 22), ("open_id_type", 23),
                             ("login_token", 29), ("orign_platform_type", 99)]:
            f = req.field.add()
            f.name, f.number, f.type, f.label = name, number, _F.TYPE_STRING, _F.LABEL_OPTIONAL

        res = fd.message_type.add()
        res.name = "LoginRes"
        for name, number, ftype, label in _LOGIN_RES_FIELDS:
            f = res.field.add()
            f.name, f.number, f.type, f.label = name, number, ftype, label

        pool.Add(fd)
    return (message_factory.GetMessageClass(pool.FindMessageTypeByName(f"{_PROTO_PACKAGE}.LoginReq")),
            message_factory.GetMessageClass(pool.FindMessageTypeByName(f"{_PROTO_PACKAGE}.LoginRes")))


LoginReq, LoginRes = _build_messages()


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def normalize_region(r):
    if not r:
        return None
    r = str(r).strip().upper()
    return REGION_MAP.get(r, r)


def region_to_url(region):
    if not region:
        return "N/A"
    region = str(region).upper()
    override = os.environ.get(f"FF_LOGIN_URL_{region}")
    if override:
        return override.rstrip("/")
    host = REGION_URL.get(region)
    if host:
        return f"https://{host}"
    return f"https://client.{region.lower()}.freefiremobile.com"


def encrypt_message(key, iv, plaintext):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, AES.block_size))


def decrypt_message(key, iv, ciphertext):
    if not ciphertext or len(ciphertext) % 16 != 0:
        return ciphertext
    try:
        return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), AES.block_size)
    except Exception:
        return ciphertext


def decode_jwt_payload(token):
    if not token or token == "N/A":
        return {}
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        p = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(p))
    except Exception:
        return {}


_decode_jwt_payload = decode_jwt_payload  # backwards compatible alias


def get_oauth_token(uid, password):
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
    }
    data = {
        "uid": str(uid),
        "password": str(password),
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067",
    }
    try:
        res = requests.post(OAUTH_URL, headers=headers, data=data, timeout=15, verify=False)
        if res.status_code != 200:
            return None
        j = res.json()
        if "access_token" in j and "open_id" in j:
            return j
        return None
    except Exception:
        return None


def _major_login_headers():
    # X-GA-SV is mandatory: without it MajorLogin answers 400 SignError1.
    return {
        "User-Agent": MAJOR_LOGIN_UA,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Expect": "100-continue",
        "X-Unity-Version": X_UNITY_VERSION,
        "X-GA": "v1 1",
        "X-GA-SV": X_GA_SV,
        "ReleaseVersion": RELEASE_VERSION,
    }


JWT_RE = re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+")
URL_RE = re.compile(r"https://[a-z0-9][a-z0-9.\-]{3,60}")


def _parse_login_res(raw):
    for payload in (raw, decrypt_message(AES_KEY, AES_IV, raw)):
        msg = LoginRes()
        try:
            msg.ParseFromString(payload)
            if msg.token:
                return msg
        except Exception:
            pass
        # The real response does not always match our LoginRes schema, but the
        # token and server_url are plain strings inside it — pull them out.
        txt = payload.decode("utf-8", "ignore")
        m = JWT_RE.search(txt)
        if not m:
            continue
        msg = LoginRes()
        msg.token = m.group(0)
        url = URL_RE.search(txt)
        if url:
            msg.server_url = url.group(0).rstrip("`")
        meta = decode_jwt_payload(msg.token)
        msg.lock_region = meta.get("lock_region") or meta.get("noti_region") or ""
        msg.account_id = int(meta.get("account_id") or 0)
        return msg
    return None


def major_login(access_token, open_id, hosts=None):
    """Try each login host; return (LoginRes, host) or (None, last_error)."""
    req = LoginReq(open_id=open_id, open_id_type="4",
                   login_token=access_token, orign_platform_type="4")
    payload = encrypt_message(AES_KEY, AES_IV, req.SerializeToString())
    last = "no host"
    for url in (hosts or MAJOR_LOGIN_HOSTS):
        try:
            r = requests.post(url, data=payload, headers=_major_login_headers(),
                              verify=False, timeout=20, allow_redirects=False)
        except Exception as e:
            last = f"{url} -> {type(e).__name__}"
            continue
        if r.status_code != 200:
            last = f"{url} -> {r.status_code} {r.content[:40]!r}"
            continue
        res = _parse_login_res(r.content)
        if res is not None:
            return res, url
        last = f"{url} -> 200 but no token"
    return None, last


def build_response(success, uid, region=None, token=None, account_id=None,
                   nickname=None, server_url=None, status_code=200):
    region_code = normalize_region(region) if region else None
    login_url = (server_url or "").rstrip("/") or (
        region_to_url(region_code) if region_code else "N/A")
    return {
        "Success": bool(success),
        "Nickname": nickname or "",
        "Account_uid": str(account_id) if account_id else str(uid),
        "Region": region_code or "N/A",
        "Jwt_Token": token or "N/A",
        "Login_url": login_url,
        "Server_url": server_url or "",
        "Timestamp": int(time.time()),
        "Ob_version": RELEASE_VERSION,
        "Status_Code": status_code,
    }


def generate(uid, password, hosts=None):
    """Return the token envelope for one account, or None on failure."""
    tok = get_oauth_token(uid, password)
    if not tok:
        return None
    res, _ = major_login(tok["access_token"], tok["open_id"], hosts)
    if res is None:
        return None
    meta = decode_jwt_payload(res.token)
    return build_response(
        True, uid,
        region=res.lock_region or meta.get("lock_region"),
        token=res.token,
        account_id=res.account_id or meta.get("account_id"),
        nickname=res.ip_city or None,
        server_url=res.server_url,
    )


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("usage: python jwt_gen.py <uid> <password>")
        raise SystemExit(1)
    out = generate(sys.argv[1], sys.argv[2])
    if not out:
        print(json.dumps({"Success": False, "reason": "oauth or MajorLogin failed"}))
        raise SystemExit(2)
    masked = dict(out)
    t = masked.pop("Jwt_Token")
    masked["Jwt_Token"] = f"{t[:12]}...{t[-6:]} ({len(t)} chars)"
    print(json.dumps(masked, indent=2))
    exp = decode_jwt_payload(t).get("exp")
    if exp:
        print("exp:", time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(exp)))
