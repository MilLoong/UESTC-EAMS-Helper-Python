from __future__ import annotations

import base64
import json
import secrets
import time
import os
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests.cookies import create_cookie

try:
    import rsa
except ImportError:
    rsa = None  # type: ignore

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
except ImportError:
    AES = None  # type: ignore
    pad = None  # type: ignore


# -------------------------------------------------------------------------
# 配置：移动教务站点地址、Cookie 快照与结果文件名
# -------------------------------------------------------------------------

BASE = os.environ.get("UESTC_EAMSAPP_BASE", "https://eamsapp.uestc.edu.cn").strip().rstrip("/") or (
    "https://eamsapp.uestc.edu.cn"
)

_BASIC = os.environ.get("UESTC_EAMSAPP_AUTHORIZATION_BASIC", "YXBwOmFwcF9zZWNyZXQ=").strip()
_EAMSAPP_HOST = "eamsapp.uestc.edu.cn"
# 可选：统计类 Cookie，顺序与浏览器一致
_EAMSAPP_OPTIONAL_COOKIE_ORDER = ("_ga", "_ga_968CMWQK03")
COOKIE_SNAPSHOT_FILENAME = "session_cookies.json"
OUTPUT_JSON_FILES = {
    "timetable": "timetable.json",
    "grades": "grades.json",
    "exam": "exam.json",
    "all": "all.json",
}
CAS_LOGIN_API = f"{BASE}/api/blade-auth/cas-login"
# 统一身份登录成功后，跳回移动教务站点用的地址
EAMSAPP_CAS_SERVICE = os.environ.get(
    "UESTC_CAS_SERVICE",
    f"{CAS_LOGIN_API}?redirectUrl={BASE}",
).strip()



# -------------------------------------------------------------------------
# 统一身份登录（学号密码、短信验证）
# -------------------------------------------------------------------------
_dbg = os.environ.get("UESTC_DEBUG", "1").strip().lower()
DEBUG_MODE = _dbg not in ("0", "false", "no", "off", "")
DEBUG_VERBOSE = os.environ.get("UESTC_DEBUG_VERBOSE", "").strip().lower() in (
    "1", "true", "yes",
)
CAS_BASE_URL = "https://idas.uestc.edu.cn/authserver"
_EAMS_ORIGIN = "https://eams.uestc.edu.cn"
BASE_URL = _EAMS_ORIGIN
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,*/*;q=0.8"
    ),
    "Upgrade-Insecure-Requests": "1",
    "Referer": "https://idas.uestc.edu.cn/authserver/login",
}
_EAMS_UA_DEFAULT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0"
)
EAMS_BROWSER_UA = os.environ.get("UESTC_EAMS_USER_AGENT", _EAMS_UA_DEFAULT).strip()
_EAMS_SEC_CH_UA_DEFAULT = (
    '"Chromium";v="148", "Microsoft Edge";v="148", "Not/A)Brand";v="99"'
)
EAMS_SEC_CH_UA = os.environ.get("UESTC_EAMS_SEC_CH_UA", _EAMS_SEC_CH_UA_DEFAULT).strip()
_AES_CHARS = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"


def _cas_service_raw() -> str:
    return os.environ.get("UESTC_CAS_SERVICE", EAMSAPP_CAS_SERVICE).strip()


def _cas_service_url_encoded() -> str:
    return urllib.parse.quote(_cas_service_raw(), safe="")


def _cas_login_phase_ok(session: requests.Session, ticket_url: str = "") -> bool:
    """登录完成后，检查移动教务站点是否已建立有效会话。"""
    if ticket_url and "ticket=" in ticket_url.lower():
        login_ref = f"{CAS_BASE_URL}/login?service={_cas_service_url_encoded()}"
        _consume_cas_service_ticket_url(session, ticket_url, login_ref)
    if _pick_jwt_jsessionid_from_session(session):
        return True
    if "eamsapp" in _cas_service_raw().lower():
        return bool(find_eamsapp_ticket_url(session))
    return bool(session.cookies.get("CASTGC"))


def _url_path_only(url: str, query_max: int = 48) -> str:
    """调试：只打印 URL 路径，避免刷屏。"""
    try:
        p = urllib.parse.urlparse(url or "")
        q = p.query or ""
        if len(q) > query_max:
            q = q[:query_max] + "…"
        return f"{p.path}?{q}" if q else (p.path or url or "")
    except Exception:
        return (url or "")[:96]


def read_login_credentials() -> Tuple[str, str]:
    """学号与统一身份认证密码：环境变量优先，否则在终端明文输入（与常见 input 一致）。"""
    username = os.environ.get("UESTC_USERNAME", "").strip()
    password = os.environ.get("UESTC_PASSWORD", "").strip()
    if username and password:
        return username, password
    if not sys.stdin.isatty():
        print(
            "❌ 非交互环境未设置账号口令：请设置环境变量 UESTC_USERNAME、UESTC_PASSWORD，"
            "或在 PowerShell/CMD 终端直接运行本脚本以手动输入。"
        )
        sys.exit(1)
    print("\n—— 统一身份认证：请输入账号密码——")
    if not username:
        username = input("学号 / 用户名: ").strip()
    if not password:
        password = input("统一身份认证密码: ").strip()
    if not username or not password:
        print("❌ 用户名和密码不能为空")
        sys.exit(1)
    return username, password
def _random_string_idas(length: int) -> str:
    return "".join(secrets.choice(_AES_CHARS) for _ in range(length))
def encrypt_password_idas(password: str, pwd_encrypt_salt: str) -> str:
    """按登录页要求加密密码。"""
    key = pwd_encrypt_salt.strip().encode("utf-8")
    iv = _random_string_idas(16).encode("utf-8")
    plaintext = (_random_string_idas(64) + password).encode("utf-8")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return base64.b64encode(ciphertext).decode("ascii")
def extract_pwd_encrypt_salt(html: str) -> Optional[str]:
    for pat in (
        r'id="pwdEncryptSalt"[^>]*value="([^"]+)"',
        r'id=\'pwdEncryptSalt\'[^>]*value=\'([^\']+)\'',
        r'name="pwdEncryptSalt"[^>]*value="([^"]+)"',
        r'value="([^"]+)"[^>]*id="pwdEncryptSalt"',
    ):
        m = re.search(pat, html, re.I)
        if m:
            return m.group(1)
    return None
def extract_public_key_simple(html: str) -> Optional[str]:
    """旧版登录页 RSA 公钥（备用）。"""
    if rsa is None:
        return None
    for pattern in (
        r'var\s+publicKey\s*=\s*["\']([A-Za-z0-9+/=\s]+)["\']',
        r'publicKey["\']?\s*:\s*["\']([A-Za-z0-9+/=\s]+)["\']',
    ):
        m = re.search(pattern, html, re.I)
        if m:
            k = m.group(1).strip().replace("\n", "").replace("\r", "")
            if len(k) > 80:
                return k
    return None
def rsa_encrypt(password: str, public_key_str: str) -> str:
    if rsa is None:
        raise RuntimeError("需要安装 rsa 库: pip install rsa")
    public_key_str = public_key_str.replace("\n", "").replace("\r", "").strip()
    public_key = rsa.PublicKey.load_pkcs1_openssl_pem(
        f"-----BEGIN PUBLIC KEY-----\n{public_key_str}\n-----END PUBLIC KEY-----".encode()
    )
    encrypted = rsa.encrypt(password.encode(), public_key)
    return base64.b64encode(encrypted).decode()
def encrypt_login_password(html: str, password: str) -> Tuple[str, str]:
    """返回 (encrypted_password, method_desc)。"""
    salt = extract_pwd_encrypt_salt(html)
    if salt:
        return encrypt_password_idas(password, salt), "AES(CryptoJS-compatible)"
    pk = extract_public_key_simple(html)
    if pk:
        return rsa_encrypt(password, pk), "RSA"
    raise RuntimeError(
        "页面中既无 pwdEncryptSalt 也无 publicKey，无法加密密码。"
    )
def _is_multifactor_reauth(url: str, html: str) -> bool:
    """是否进入短信等二次认证页面。"""
    u = url.lower()
    if "reauthcheck" in u or "isMultifactor=true" in u or "multifactor" in u:
        return True
    h = html[:8000].lower()
    return "二次认证" in html or "多因素" in html or "reauth" in h
def _xhr_headers(referer: str) -> Dict[str, str]:
    """二次认证页面向服务器发请求时用的请求头。"""
    return {
        **HEADERS,
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Referer": referer,
    }
def _service_from_reauth_url(reauth_page_url: str) -> str:
    """从二次认证页 URL 解析登录回调地址。"""
    q = urllib.parse.parse_qs(urllib.parse.urlparse(reauth_page_url).query)
    vals = q.get("service")
    if vals:
        return vals[0]
    return _cas_service_raw()


# -------------------------------------------------------------------------
# 登录状态快照（session_cookies.json）
# -------------------------------------------------------------------------

def _session_cookies_snapshot_path() -> str:
    """当前工作目录下的 session_cookies.json（已在 .gitignore，勿提交）。"""
    return str(Path.cwd() / COOKIE_SNAPSHOT_FILENAME)


def _save_session_cookies_to_file(session: requests.Session, path: str) -> None:
    """将 Session 全部 Cookie（多域）写入 JSON；下次同目录运行可免输密码。"""
    recs: List[Dict[str, Any]] = []
    for c in session.cookies:
        name = getattr(c, "name", None)
        if not name:
            continue
        recs.append(
            {
                "name": name,
                "value": getattr(c, "value", "") or "",
                "domain": getattr(c, "domain", "") or "",
                "path": (getattr(c, "path", None) or "/"),
                "expires": getattr(c, "expires", None),
                "secure": bool(getattr(c, "secure", False)),
            }
        )

    pp = Path(path)
    pp.parent.mkdir(parents=True, exist_ok=True)
    with open(pp, "w", encoding="utf-8") as f:
        json.dump(recs, f, ensure_ascii=False, indent=2)
    if not recs:
        if DEBUG_VERBOSE:
            print(f"⚠️ 未能写入 Cookie 快照（Session 为空）：{path}", file=sys.stderr)
        return
def _load_session_cookies_from_file(session: requests.Session, path: str) -> int:
    """从 JSON 恢复 Cookie，返回条目数。"""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Cookie 快照须为 JSON 数组")
    n = 0
    for item in data:
        if not isinstance(item, dict) or "name" not in item or "value" not in item:
            continue
        name = str(item["name"])
        value = str(item["value"])
        domain = (item.get("domain") or "").strip() or "eams.uestc.edu.cn"
        cpath = (item.get("path") or "").strip() or "/"
        exp = item.get("expires")
        expires_kw: Dict[str, Any] = {}
        if isinstance(exp, int) and exp > 0:
            expires_kw["expires"] = exp
        session.cookies.set_cookie(
            create_cookie(
                name=name,
                value=value,
                domain=domain.lstrip(".").strip() or "eams.uestc.edu.cn",
                path=cpath,
                **expires_kw,
            )
        )
        n += 1
    return n


def _eams_browser_headers(referer: Optional[str] = None) -> Dict[str, str]:
    """访问教务相关页面时的浏览器请求头。"""
    h = {**HEADERS}
    h["User-Agent"] = EAMS_BROWSER_UA
    h["Referer"] = referer or f"{BASE_URL}/eams/home.action"
    # 模拟 Edge 浏览器的客户端标识头
    h["sec-ch-ua-platform"] = '"Windows"'
    h["sec-ch-ua"] = EAMS_SEC_CH_UA
    h["sec-ch-ua-mobile"] = "?0"
    return h


def _reauth_submit_response_summary(r: requests.Response) -> str:
    """调试：二次认证提交结果摘要。"""
    if r.status_code != 200:
        return f"HTTP {r.status_code}"
    try:
        p = r.json()
    except (json.JSONDecodeError, ValueError):
        t = (r.text or "").strip()
        return f"非JSON，正文前80字: {t[:80]!r}" if t else "空正文"
    if not isinstance(p, dict):
        return f"JSON 非对象: {type(p).__name__}"
    code = p.get("code")
    msg = (p.get("msg") or p.get("message") or "")[:120]
    extra = f" msg={msg!r}" if msg else ""
    return f"code={code!r}{extra}"
def _print_cas_login_chain_summary(r: requests.Response, label: str) -> None:
    """打印整页 GET login 的终点与最近几条重定向（路径截断，避免刷屏）。"""
    if not DEBUG_VERBOSE:
        return
    print(f"  {label}: HTTP {r.status_code} {_url_path_only(r.url or '')}")
    hops = list(r.history)[-5:]
    for h in hops:
        loc = h.headers.get("Location") or ""
        if loc:
            print(f"    ← {h.status_code} {_url_path_only(loc)}")
def _consume_cas_service_ticket_url(
    session: requests.Session, ticket_page_url: str, cas_login_page_url: str
) -> None:
    """登录成功后，用临时票据换取移动教务站点会话。"""
    tu = (ticket_page_url or "").strip()
    if not tu or "ticket=" not in tu.lower():
        return
    low = tu.lower()
    if "eamsapp.uestc.edu.cn" in low and "cas-login" in low:
        consume_eamsapp_cas_ticket(session, tu, referer=cas_login_page_url)
    elif "online.uestc.edu.cn" in low:
        session.get(tu, headers=_eams_browser_headers(cas_login_page_url), allow_redirects=True, timeout=60)
    else:
        session.get(
            tu,
            headers=_eams_browser_headers(cas_login_page_url),
            allow_redirects=True,
            timeout=60,
        )
def _follow_idas_login_service_to_eams(
    session: requests.Session, service_raw: str, referer: str
) -> None:
    """手动跟随登录跳转链，避免丢失 Cookie。"""
    service_q = urllib.parse.quote(service_raw, safe="")
    login_url = f"{CAS_BASE_URL}/login?service={service_q}"
    url = login_url
    hdr: Dict[str, str] = {**HEADERS, "Referer": referer}
    last = r = None
    for _ in range(40):
        r = session.get(url, headers=hdr, allow_redirects=False, timeout=60)
        last = r
        if r.status_code not in (301, 302, 303, 307, 308):
            break
        loc = r.headers.get("Location")
        if not loc:
            break
        prev = url
        url = urllib.parse.urljoin(str(r.url), loc)
        hdr = {**HEADERS}
        hdr["Referer"] = (
            login_url
            if ("eams.uestc.edu.cn" in url.lower() or "online.uestc.edu.cn" in url.lower())
            else prev
        )
    if last and last.status_code in (301, 302, 303, 307, 308):
        loc = last.headers.get("Location")
        if loc:
            session.get(
                urllib.parse.urljoin(str(last.url), loc),
                headers=hdr,
                allow_redirects=True,
                timeout=60,
            )
    elif last and last.status_code == 200 and "ticket=" in (last.url or "").lower():
        _consume_cas_service_ticket_url(session, last.url or "", login_url)
    elif (
        last
        and last.status_code == 200
        and last.url
        and "eams.uestc.edu.cn" in last.url.lower()
        and "login.action" in last.url.lower()
    ):
        session.get(
            last.url,
            headers=_eams_browser_headers(login_url),
            allow_redirects=True,
            timeout=60,
        )
def _ensure_multifactor_fingerprint(session: requests.Session, referer: str) -> str:
    """生成设备指纹 Cookie（二次认证需要）。"""
    bfp = session.cookies.get("MULTIFACTOR_BROWSER_FINGERPRINT")
    if not bfp:
        bfp = secrets.token_hex(16).upper()
        session.cookies.set_cookie(
            create_cookie(
                name="MULTIFACTOR_BROWSER_FINGERPRINT",
                value=bfp,
                domain="idas.uestc.edu.cn",
                path="/",
            )
        )
        if DEBUG_VERBOSE:
            print("  → 已生成设备指纹并完成 bfp/info")
    xhr = _xhr_headers(referer)
    ts = int(time.time() * 1000)
    session.get(
        f"{CAS_BASE_URL}/bfp/info",
        params={"bfp": bfp, "_": ts},
        headers=xhr,
        timeout=30,
    )
    return bfp
def _parse_reauth_uuid(html: str) -> str:
    """二次认证表单隐藏域 uuid（多数为空字符串）。"""
    um = re.search(r'name=["\']uuid["\'][^>]*value=["\']([^"\']*)["\']', html, re.I)
    return um.group(1) if um else ""
def _debug_log_reauth_send_hints(html: str) -> None:
    """调试：扫描二次认证页里可能的发验证码接口。"""
    if not DEBUG_MODE or not DEBUG_VERBOSE or not html:
        return
    hints: List[str] = []
    for m in re.finditer(
        r'(?:https?://idas\.uestc\.edu\.cn)?(/authserver/[^\s"\'<>]+)', html, re.I
    ):
        path = m.group(1)
        low = path.lower()
        if any(
            k in low
            for k in (
                "send",
                "sms",
                "message",
                "mobile",
                "dynamic",
                "otp",
                "verify",
            )
        ):
            if path not in hints:
                hints.append(path)
        if len(hints) >= 12:
            break
    if hints:
        print("  ℹ️「发送验证码」相关 URL（自页面 HTML 扫描，需在浏览器里核对方法与参数）:")
        for p in hints:
            print(f"     · {p}")
    else:
        print(
            "  ℹ️ 页面里未找到明显的发验证码接口；"
            "验证码可能已由学校提前下发，或在手机 APP 里查看。"
        )
def _parse_reauth_params_from_html(html: str) -> Tuple[str, str]:
    """从二次认证页 HTML 解析用户与验证方式。"""
    uid_m = re.search(r'"reAuthUserId"\s*:\s*"([^"]*)"', html)
    type_m = re.search(r'"reAuthType"\s*:\s*"([^"]*)"', html)
    return (
        uid_m.group(1).strip() if uid_m else "",
        type_m.group(1).strip() if type_m else "",
    )
def _parse_reauth_is_sleep_account(html: str) -> str:
    """是否弹出「信任此设备」；影响提交字段。"""
    m = re.search(r'"isSleepAccount"\s*:\s*"([^"]*)"', html)
    return m.group(1).strip() if m else "1"
def _parse_reauth_service_from_html(html: str) -> Optional[str]:
    """从页面脚本读取登录回调地址。"""
    m = re.search(r'"service"\s*:\s*"([^"]+)"', html)
    if not m:
        return None
    s = m.group(1).replace(r"\/", "/")
    return s if s.startswith("http") else None
def _idas_login_referer_for_reauth_page(service_raw: str) -> str:
    """二次认证页面对应的登录页来源地址。"""
    return f"{CAS_BASE_URL}/login?service={urllib.parse.quote(service_raw, safe='')}"
def _reauth_submit_failure_message(payload: dict) -> Optional[str]:
    """判断二次认证接口是否返回失败。"""
    if not isinstance(payload, dict):
        return None
    code = payload.get("code")
    if code == "reAuth_failed":
        return str(payload.get("msg") or payload.get("message") or "").strip() or "二次认证未通过"
    if code == "reAuth_unauthorized":
        return str(payload.get("msg") or payload.get("message") or "").strip() or "未授权"
    if payload.get("success") is False:
        return str(payload.get("message") or payload.get("msg") or "").strip() or "二次认证未通过"
    return None
def _reauth_send_auth_code_type_name(reauth_type: str) -> Optional[str]:
    """短信验证码类型名（随验证方式不同）。"""
    return {
        "3": "reAuthDynamicCodeType",
        "4": "reAuthWChatDynamicCodeType",
        "5": "reAuthCpdailyDynamicCodeType",
        "11": "reAuthEmailDynamicCodeType",
        "12": "reAuthDingTalkDynamicCodeType",
        "13": "reAuthWeLinkDynamicCodeType",
    }.get(reauth_type.strip())
def _mobile_from_reauth_send_payload(payload: dict) -> Optional[str]:
    """发码接口 JSON：顶层 mobile 或 data.mobile。"""
    m = payload.get("mobile")
    if isinstance(m, str) and m.strip():
        return m.strip()
    data = payload.get("data")
    if isinstance(data, dict):
        m2 = data.get("mobile")
        if isinstance(m2, str) and m2.strip():
            return m2.strip()
    return None
def _mobile_hint_from_text(text: str) -> Optional[str]:
    """从接口文案里抽脱敏手机号，例如 138****5678。"""
    if not text:
        return None
    m = re.search(r"1\d{10}|1\d[\d\*]{4,12}\d{4}", text)
    return m.group(0) if m else None
def _reauth_send_code_outcome(payload: dict) -> Tuple[Optional[str], Optional[bool], str]:
    """发码 JSON → 手机号提示、是否发送成功、简短说明。"""
    mob = _mobile_from_reauth_send_payload(payload)
    msg = (payload.get("returnMessage") or payload.get("message") or "").strip()
    if not mob and msg:
        mob = _mobile_hint_from_text(msg)
    res = payload.get("res")
    if res in ("success", "wechat_success", "cpdaily_success"):
        return mob, True, msg
    if res == "code_time_fail":
        return mob, False, (msg or str(res))
    if msg or res:
        piece = f"{res} {msg}".strip() if res else msg
        return mob, False, piece
    return mob, None, ""
def _trigger_reauth_send_code_if_configured(
    session: requests.Session, referer: str, html: str
) -> Tuple[Optional[str], Optional[bool], str]:
    """自动发短信；返回 (手机号或 None, 是否成功 True/False/未知 None, 说明或内部标记 skip/no_params)。"""
    if os.environ.get("UESTC_REAUTH_SKIP_PHONE_SEND", "").strip().lower() in (
        "1",
        "true",
        "yes",
    ):
        return None, None, "skip"

    raw = os.environ.get("UESTC_REAUTH_SEND_CODE_URL", "").strip()
    if raw:
        method = os.environ.get("UESTC_REAUTH_SEND_CODE_METHOD", "POST").strip().upper()
        if raw.startswith("http://") or raw.startswith("https://"):
            url = raw
        else:
            if not raw.startswith("/"):
                raw = "/" + raw
            url = f"https://idas.uestc.edu.cn{raw}"
        xhr = _xhr_headers(referer)
        if method == "GET":
            r = session.get(url, headers=xhr, timeout=30)
        else:
            r = session.post(url, headers=xhr, data="", timeout=30)
        if DEBUG_VERBOSE:
            print(f"  [VERBOSE] 自定义发码 {method} {url!r} → HTTP {r.status_code}")
        if r.status_code != 200:
            return None, False, f"HTTP {r.status_code}"
        try:
            payload = r.json()
            if isinstance(payload, dict):
                m, ok, d = _reauth_send_code_outcome(payload)
                return m, ok, d
        except (json.JSONDecodeError, ValueError):
            pass
        if DEBUG_VERBOSE and (r.text or ""):
            preview = (r.text or "")[:200].replace("\n", " ")
            print(f"     响应预览: {preview!r}")
        return None, None, ""

    uid, rt = _parse_reauth_params_from_html(html)
    act = _reauth_send_auth_code_type_name(rt) if rt else None
    if not uid or not act:
        return None, None, "no_params"

    url = f"{CAS_BASE_URL}/dynamicCode/getDynamicCodeByReauth.do"
    xhr = _xhr_headers(referer)
    headers = {
        **xhr,
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "Origin": "https://idas.uestc.edu.cn",
    }
    data = {"userName": uid, "authCodeTypeName": act}
    r = session.post(url, headers=headers, data=data, timeout=30)
    if DEBUG_VERBOSE:
        preview = (r.text or "")[:400].replace("\n", " ")
        print(f"  [VERBOSE] getDynamicCodeByReauth HTTP {r.status_code}: {preview!r}")
    if r.status_code != 200:
        return None, False, f"HTTP {r.status_code}"
    try:
        payload = r.json()
        if isinstance(payload, dict):
            return _reauth_send_code_outcome(payload)
    except (json.JSONDecodeError, ValueError):
        if DEBUG_VERBOSE and (r.text or ""):
            preview = (r.text or "")[:400].replace("\n", " ")
            print(f"     响应(非JSON): {preview!r}")
    return None, None, ""
def _prompt_reauth_user_input(dynamic_preset: str) -> str:
    """交互或使用环境变量 UESTC_REAUTH_DYNAMIC_CODE。"""
    d = dynamic_preset.strip()
    if sys.stdin.isatty():
        if not d:
            d = input("短信验证码: ").strip()
    elif not d:
        print("  非交互环境请设置 UESTC_REAUTH_DYNAMIC_CODE。")
    return d
def _report_reauth_sms_send(
    mob: Optional[str], send_ok: Optional[bool], detail: str
) -> None:
    """二次认证：只汇报手机号与发码成败。"""
    print("\n🔐 二次认证")
    if detail == "skip":
        print("  已跳过自动发短信。")
        return
    if detail == "no_params":
        print("  ⚠️ 未能自动发短信，请在浏览器获取验证码后再输入。")
        return
    if mob:
        print(f"  手机号: {mob}")
    if send_ok is True:
        print("  短信验证码：已发送")
    elif send_ok is False:
        tail = f"，{detail}" if detail else ""
        print(f"  短信验证码：发送失败{tail}")
    elif detail and DEBUG_VERBOSE:
        print(f"  [VERBOSE] 发码: {detail}")
def complete_idas_reauth(session: requests.Session, reauth_page_url: str) -> bool:
    """完成短信二次认证：发码 → 输入验证码 → 提交。"""
    referer = reauth_page_url.split("#")[0]
    service = _service_from_reauth_url(reauth_page_url)
    login_form_referer = _idas_login_referer_for_reauth_page(service)

    r_page = session.get(
        reauth_page_url,
        headers={**HEADERS, "Referer": login_form_referer},
        timeout=60,
    )
    html = r_page.text or ""

    session.get(f"{CAS_BASE_URL}/tenant/info", headers=_xhr_headers(referer), timeout=30)

    _ensure_multifactor_fingerprint(session, referer)

    # 设备指纹请求可能刷新会话，再拉一次二次认证页
    r_refresh = session.get(
        reauth_page_url,
        headers={**HEADERS, "Referer": login_form_referer},
        timeout=60,
    )
    if r_refresh.status_code == 200 and (r_refresh.text or "").strip():
        html = r_refresh.text

    svc_html = _parse_reauth_service_from_html(html)
    if svc_html:
        service = svc_html
        login_form_referer = _idas_login_referer_for_reauth_page(service)

    if DEBUG_MODE:
        _debug_log_reauth_send_hints(html)

    mob, send_ok, send_detail = _trigger_reauth_send_code_if_configured(
        session, referer, html
    )
    _report_reauth_sms_send(mob, send_ok, send_detail)

    dynamic_code = _prompt_reauth_user_input(
        os.environ.get("UESTC_REAUTH_DYNAMIC_CODE", "").strip()
    )

    if not dynamic_code:
        print("  ❌ 未填写短信验证码")
        return False

    xhr = _xhr_headers(referer)
    session.post(
        f"{CAS_BASE_URL}/systemTime",
        headers={**xhr, "Accept": "*/*"},
        data="",
        timeout=30,
    )

    uuid_from_html = _parse_reauth_uuid(html)

    _uid_html, reauth_type_html = _parse_reauth_params_from_html(html)
    reauth_type = (
        os.environ.get("UESTC_REAUTH_TYPE", "").strip() or reauth_type_html or "3"
    )
    is_sleep = _parse_reauth_is_sleep_account(html)

    submit_data: Dict[str, str] = {
        "service": service,
        "reAuthType": reauth_type,
        "isMultifactor": "true",
        "password": "",
        "dynamicCode": dynamic_code,
        "uuid": uuid_from_html,
        "answer1": "",
        "answer2": "",
        "otpCode": "",
    }
    # 「信任此设备」时附加相应字段
    if is_sleep == "0":
        trust = os.environ.get("UESTC_REAUTH_TRUST_DEVICE", "").strip().lower() in (
            "1",
            "true",
            "yes",
        )
        submit_data["skipTmpReAuth"] = "true" if trust else "false"

    submit_headers = {
        **xhr,
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "Origin": "https://idas.uestc.edu.cn",
    }
    r_submit = session.post(
        f"{CAS_BASE_URL}/reAuthCheck/reAuthSubmit.do",
        data=submit_data,
        headers=submit_headers,
        timeout=60,
    )
    if DEBUG_VERBOSE:
        preview = (r_submit.text or "")[:400].replace("\n", " ")
        print(f"     reAuthSubmit 响应 {r_submit.status_code}: {preview!r}")

    if r_submit.status_code != 200:
        print(f"  ❌ 二次认证提交失败 HTTP {r_submit.status_code}")
        return False

    try:
        payload = r_submit.json()
        if isinstance(payload, dict):
            fail_msg = _reauth_submit_failure_message(payload)
            if fail_msg:
                print(f"  ❌ 二次认证失败: {fail_msg}")
                return False
            if DEBUG_VERBOSE:
                print(f"  [VERBOSE] reAuthSubmit: {payload!r}")
    except (json.JSONDecodeError, ValueError):
        raw = (r_submit.text or "").strip()
        low = raw.lower()
        if "reauth_failed" in low.replace(" ", "") or "reauth_unauthorized" in low.replace(
            " ", ""
        ):
            print("  ❌ 二次认证失败")
            return False
        if '"success":false' in low or "success:false" in low.replace(" ", ""):
            print("  ❌ 二次认证失败")
            return False

    if DEBUG_VERBOSE:
        print(f"  reAuthSubmit 摘要: {_reauth_submit_response_summary(r_submit)}")

    service_q = urllib.parse.quote(service, safe="")
    login_after = f"{CAS_BASE_URL}/login?service={service_q}"

    # 提交成功后按浏览器行为跳转登录页
    r_cas = session.get(
        login_after,
        headers={**HEADERS, "Referer": referer},
        allow_redirects=True,
        timeout=60,
    )
    _print_cas_login_chain_summary(r_cas, "登录跳转后")

    if _cas_login_phase_ok(session, ""):
        return True

    print("  登录跳转后会话尚未就绪，正在继续跟随页面跳转…")
    _follow_idas_login_service_to_eams(session, service, referer)
    if _cas_login_phase_ok(session, ""):
        return True

    r_final = session.get(
        login_after,
        headers={**HEADERS, "Referer": referer},
        allow_redirects=True,
        timeout=60,
    )
    _print_cas_login_chain_summary(r_final, "再次登录跳转后")
    if "eams.uestc.edu.cn" in (r_final.url or "").lower() and "login.action" in (
        r_final.url or ""
    ).lower():
        session.get(
            f"{BASE_URL}/eams/login.action",
            headers=_eams_browser_headers(login_after),
            allow_redirects=True,
            timeout=60,
        )
    online_ok = _cas_login_phase_ok(session, "")
    if online_ok:
        return True

    print(
        "  ℹ️ 二次认证已提交成功；"
        "正在继续完成登录并连接移动教务站点。"
    )
    return True


def cas_login(session: requests.Session, username: str, password: str) -> bool:
    """统一身份网站：提交学号密码并完成跳转。"""
    print("正在登录…")

    cas_login_url = f"{CAS_BASE_URL}/login?service={_cas_service_url_encoded()}"
    response = session.get(cas_login_url, headers=HEADERS, allow_redirects=True)

    if DEBUG_VERBOSE:
        print(f"\n=== 调试信息 VERBOSE ===")
        print(f"统一身份登录页: {cas_login_url}")
        print(f"最终URL: {response.url}，HTTP {response.status_code}，{len(response.text)} 字节")

    # 若本地已有旧会话，可能直接跳进其它门户站，需判断是否仍有效
    fin0 = response.url or ""
    if "online.uestc.edu.cn" in fin0.lower() and "idas.uestc.edu.cn" not in fin0.lower():
        if _cas_login_phase_ok(session, ""):
            _login_success_msg_debug_only()
            return True
        print(
            "⚠️ 检测到旧的门户登录状态，但移动教务尚不可用。\n"
            "   将清空本会话 Cookie 并重新打开统一身份登录页。"
        )
        session.cookies.clear()
        response = session.get(cas_login_url, headers=HEADERS, allow_redirects=True)
        if DEBUG_VERBOSE:
            print(
                f"  [登录] 重试 GET 登录页 终址={response.url!r} HTTP={response.status_code}"
            )

    # 旧 Cookie 可能跳过密码页；无效则清空后重新打开登录页
    if "eams.uestc.edu.cn/eams" in response.url:
        if _cas_login_phase_ok(session, ""):
            _login_success_msg_debug_only()
            return True
        print(
            "⚠️ 检测到旧的教务登录跳转，但当前无法查询课表。\n"
            "   将清空本会话 Cookie 并重新打开统一身份登录页（随后可能出现短信验证）。"
        )
        session.cookies.clear()
        response = session.get(cas_login_url, headers=HEADERS, allow_redirects=True)
        if DEBUG_VERBOSE:
            print(f"  [登录] 重试 GET 登录页 终址={response.url!r} HTTP={response.status_code}")

    login_html = response.text

    # 清空 Cookie 后仍无法进入登录页
    if "eams.uestc.edu.cn/eams" in response.url:
        if _cas_login_phase_ok(session, ""):
            _login_success_msg_debug_only()
            return True
        print(
            "❌ 清除 Cookie 后仍无法完成登录。"
            "请设置 UESTC_FRESH_LOGIN=1 重试，或粘贴浏览器 Cookie。"
        )
        return False

    # 清空 Cookie 后仍停留在其它门户页
    fin1 = response.url or ""
    if "online.uestc.edu.cn" in fin1.lower() and "idas.uestc.edu.cn" not in fin1.lower():
        if _cas_login_phase_ok(session, ""):
            _login_success_msg_debug_only()
            return True
        print(
            "❌ 清除 Cookie 后仍无法完成登录。"
            "请设置 UESTC_FRESH_LOGIN=1 重试，或粘贴浏览器 Cookie。"
        )
        return False

    # 登录表单隐藏字段
    execution_patterns = [
        r'id="execution"[^>]*name="execution"[^>]*value="([^"]+)"',
        r'name=["\']execution["\']\s+value=["\']([^"\']+)["\']',
        r'<input[^>]+name=["\']execution["\'][^>]+value=["\']([^"\']+)["\']',
    ]
    
    execution = None
    for pattern in execution_patterns:
        match = re.search(pattern, login_html, re.IGNORECASE)
        if match:
            execution = match.group(1)
            break
    
    if not execution:
        print("❌ 错误：无法读取登录页必要参数")
        if DEBUG_VERBOSE:
            print(f"   [VERBOSE] execution 页 HTML 前2000字:\n{login_html[:2000]}...")
        return False

    if DEBUG_VERBOSE:
        print(f"✅ execution: {execution[:30]}…")

    if DEBUG_VERBOSE:
        print("\n正在检查验证码状态...")
    captcha_url = f"{CAS_BASE_URL}/checkNeedCaptcha.htl?username={username}&_=1779278494647"
    try:
        captcha_response = session.get(captcha_url, headers=HEADERS, timeout=10)
        if captcha_response.json().get("isNeed", False):
            print("❌ 错误：需要验证码，当前代码不支持")
            return False
        if DEBUG_VERBOSE:
            print("✅ 验证码检查通过")
    except Exception as e:
        print(f"⚠️ 验证码检查失败，跳过: {e}")
    
    try:
        encrypted_password, enc_method = encrypt_login_password(login_html, password)
        if DEBUG_VERBOSE:
            print(f"✅ 密码加密完成，方式 {enc_method}")
    except RuntimeError as e:
        print(f"❌ {e}")
        return False
    
    # POST 学号密码
    login_data = {
        "username": username,
        "password": encrypted_password,
        "captcha": "",
        "rememberMe": "true",
        "_eventId": "submit",
        "cllt": "userNameLogin",
        "dllt": "generalLogin",
        "lt": "",
        "execution": execution
    }
    post_headers = {
        **HEADERS,
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "https://idas.uestc.edu.cn",
        "Referer": cas_login_url,
    }
    login_response = session.post(
        f"{CAS_BASE_URL}/login?service={_cas_service_url_encoded()}",
        data=login_data,
        headers=post_headers,
        allow_redirects=True,
        timeout=60,
    )
    
    if DEBUG_VERBOSE:
        print(
            f"\n=== 登录 POST 后: {login_response.url!r} HTTP {login_response.status_code} ==="
        )
    
    url_final = login_response.url
    body = login_response.text or ""

    if _is_multifactor_reauth(url_final, body):
        if complete_idas_reauth(session, url_final):
            _login_success_msg_debug_only()
            return True
        print("\n❌ 二次认证未完成")
        if DEBUG_VERBOSE:
            print(f"   {url_final!r}\n{body[:400]}…")
        return False

    if "ticket=" in url_final.lower():
        _consume_cas_service_ticket_url(session, url_final, cas_login_url)

    if _cas_login_phase_ok(session, ""):
        _login_success_msg_debug_only()
        return True

    print(
        "\n❌ 登录未完成：请检查学号密码，或删除 session_cookies.json 后重试。"
    )
    if DEBUG_VERBOSE:
        print(f"页面内容前500字:\n{body[:500]}...")
    return False

def _cookie_retry_disabled() -> bool:
    return os.environ.get("UESTC_DISABLE_COOKIE_RETRY", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )


# -------------------------------------------------------------------------
# 登录状态校验：过期则清快照并重登
# -------------------------------------------------------------------------

def _blade_api_response_ok(r: requests.Response) -> bool:
    if r.status_code not in (200, 202):
        return False
    txt = (getattr(r, "text", "") or "").strip()
    if not txt.startswith("{"):
        return False
    try:
        obj = json.loads(txt)
    except json.JSONDecodeError:
        return False
    if not isinstance(obj, dict):
        return False
    if obj.get("success") is True:
        return True
    code = obj.get("code")
    return code in (200, 0, "200", "0")


def _blade_api_response_auth_failed(r: requests.Response) -> bool:
    if r.status_code in (401, 403):
        return True
    txt = (getattr(r, "text", "") or "").strip()
    if not txt.startswith("{"):
        return False
    try:
        obj = json.loads(txt)
    except json.JSONDecodeError:
        return False
    if not isinstance(obj, dict):
        return False
    if _blade_api_response_ok(r):
        return False
    code = obj.get("code")
    if code in (401, 403, 10001, "401", "403"):
        return True
    msg = str(obj.get("msg") or obj.get("message") or "").lower()
    return any(k in msg for k in ("登录", "token", "unauthorized", "未授权", "失效", "过期", "未登录"))


def _probe_cookie_header_ok(cookie_hdr: str) -> bool:
    """先用学期接口试一次，判断 Cookie 是否仍有效。"""
    if not cookie_hdr.strip():
        return False
    try:
        r = requests.get(
            f"{BASE}/api/ydzc-app/semester/getCurSemester",
            headers=headers_mobile_api(cookie_hdr),
            timeout=30,
        )
    except requests.RequestException:
        return False
    return _blade_api_response_ok(r)


def _relogin_after_stale_snapshot(*, retried: bool) -> str:
    print("⚠️ 登录状态已过期，正在重新登录…", flush=True)
    clear_session_cookies_snapshot()
    return resolve_cookie_via_portal_session(force_fresh=True, _retried=retried)


def session_cookies_snapshot_path() -> str:
    return _session_cookies_snapshot_path()


def clear_session_cookies_snapshot() -> bool:
    """删除本机 session_cookies.json（用户称「清缓存」）。"""
    p = session_cookies_snapshot_path()
    if not os.path.isfile(p):
        return False
    try:
        os.remove(p)
    except OSError as ex:
        print(f"⚠️ 无法删除 Cookie 快照 {p}: {ex}", file=sys.stderr)
        return False
    print(f"🗑 已清除 {COOKIE_SNAPSHOT_FILENAME}，将重新登录。", flush=True)
    return True


# -------------------------------------------------------------------------
# 访问移动教务接口前的 Cookie 处理
# -------------------------------------------------------------------------

def _debug_stderr_enabled() -> bool:
    x = os.environ.get("UESTC_DEBUG", "1").strip().lower()
    return x not in ("0", "false", "no", "off", "")


def mobile_jessionid_looks_like_jwt(val: str) -> bool:
    """Cookie 里的 JSESSIONID 是否为可用的长登录令牌。"""
    return len(val) > 20 and val.count(".") >= 2


def _cookie_domain_on_eamsapp(domain: str) -> bool:
    d = (domain or "").lstrip(".").lower()
    if not d:
        return True
    return d == _EAMSAPP_HOST or d.endswith("." + _EAMSAPP_HOST) or _EAMSAPP_HOST in d


def format_mobile_cookie_header(
    *,
    jsessionid: str,
    vjuid: str = "",
    extras: Optional[List[Tuple[str, str]]] = None,
) -> str:
    """拼装访问移动教务 API 用的 Cookie 字符串。"""
    parts: List[str] = []
    for name, val in extras or ():
        if name and val:
            parts.append(f"{name}={val}")
    if vjuid:
        parts.append(f"cookie_vjuid_portal_login={vjuid}")
    parts.append(f"JSESSIONID={jsessionid}")
    return "; ".join(parts)


def _optional_analytics_cookies_from_jar(sess: requests.Session) -> List[Tuple[str, str]]:
    seen: Dict[str, str] = {}
    for c in sess.cookies:
        nm = getattr(c, "name", "") or ""
        if nm not in _EAMSAPP_OPTIONAL_COOKIE_ORDER:
            continue
        val = str(getattr(c, "value", "") or "")
        if val:
            seen[nm] = val
    return [(k, seen[k]) for k in _EAMSAPP_OPTIONAL_COOKIE_ORDER if k in seen]


def _optional_analytics_from_cookie_header(cookie_hdr: str) -> List[Tuple[str, str]]:
    pairs: Dict[str, str] = {}
    for part in (cookie_hdr or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip()
        if k in _EAMSAPP_OPTIONAL_COOKIE_ORDER:
            pairs[k] = v.strip()
    return [(k, pairs[k]) for k in _EAMSAPP_OPTIONAL_COOKIE_ORDER if k in pairs]


def _pick_best_jsessionid_from_jar(sess: requests.Session) -> str:
    """从 Cookie 罐里挑选最合适的 JSESSIONID。"""
    eams_jwt: List[str] = []
    eams_opaque: List[str] = []
    any_jwt: List[str] = []
    any_opaque: List[str] = []
    for c in sess.cookies:
        if getattr(c, "name", "") != "JSESSIONID":
            continue
        v = str(getattr(c, "value", "") or "")
        if not v:
            continue
        on_eams = _cookie_domain_on_eamsapp(str(getattr(c, "domain", "") or ""))
        if mobile_jessionid_looks_like_jwt(v):
            (eams_jwt if on_eams else any_jwt).append(v)
        else:
            (eams_opaque if on_eams else any_opaque).append(v)
    if eams_jwt:
        return eams_jwt[-1]
    if any_jwt:
        return any_jwt[-1]
    if eams_opaque:
        return eams_opaque[-1]
    if any_opaque:
        return any_opaque[-1]
    return ""


def _pick_vjuid_from_jar(sess: requests.Session) -> str:
    for c in sess.cookies:
        if getattr(c, "name", "") == "cookie_vjuid_portal_login":
            v = str(getattr(c, "value", "") or "")
            if v:
                return v
    return ""


def _pick_jwt_jsessionid_from_session(session: requests.Session) -> str:
    for c in session.cookies:
        if getattr(c, "name", "") == "JSESSIONID":
            v = str(getattr(c, "value", "") or "")
            if mobile_jessionid_looks_like_jwt(v):
                return v
    return ""


def _parse_cas_landing_query(url: str) -> Tuple[str, str, str]:
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query, keep_blank_values=True)
    jwt = ""
    for key in ("jsessionid", "JSESSIONID"):
        for v in qs.get(key, []):
            if mobile_jessionid_looks_like_jwt(v):
                jwt = v
                break
    if not jwt:
        m = re.search(r"[?&]jsessionid=([^&]+)", url, re.I)
        if m and mobile_jessionid_looks_like_jwt(m.group(1)):
            jwt = m.group(1)
    return jwt, (qs.get("userId") or [""])[0], (qs.get("roles") or [""])[0]


def compose_eamsapp_session_cookie(session: requests.Session, jwt: str) -> str:
    return format_mobile_cookie_header(
        jsessionid=jwt,
        vjuid=_pick_vjuid_from_jar(session),
        extras=_optional_analytics_cookies_from_jar(session),
    )


def _cas_nav_headers(*, cookie: str = "", referer: str = "") -> Dict[str, str]:
    h = dict(headers_home(cookie or " "))
    if cookie:
        h["Cookie"] = cookie
    elif "Cookie" in h:
        del h["Cookie"]
    h["Sec-Fetch-Site"] = "same-site"
    if referer:
        h["Referer"] = referer
    return h


def consume_eamsapp_cas_ticket(
    session: requests.Session,
    start_url: str,
    *,
    referer: str = "https://idas.uestc.edu.cn/",
) -> str:
    """用登录票据访问移动教务站点，换取 API 令牌。"""
    url = start_url.strip()
    hdr = _cas_nav_headers(referer=referer)
    jwt = ""
    landing = ""
    for _ in range(25):
        r = session.get(url, headers=hdr, allow_redirects=False, timeout=60)
        loc = r.headers.get("Location") or ""
        if loc:
            loc = urllib.parse.urljoin(str(r.url), loc)
            j, uid, roles = _parse_cas_landing_query(loc)
            if j:
                jwt = j
                if uid or roles or "jsessionid" in loc.lower():
                    landing = loc
        if jwt and landing:
            break
        if r.status_code in (301, 302, 303, 307, 308) and loc:
            url = loc
            hdr = _cas_nav_headers(referer=str(r.url))
            continue
        break
    if jwt and landing:
        session.cookies.set("JSESSIONID", jwt, domain=_EAMSAPP_HOST, path="/")
        session.get(landing, headers=_cas_nav_headers(referer=referer), timeout=60, allow_redirects=True)
        jwt = _pick_jwt_jsessionid_from_session(session) or jwt
    elif jwt:
        session.cookies.set("JSESSIONID", jwt, domain=_EAMSAPP_HOST, path="/")
    return jwt or _pick_jwt_jsessionid_from_session(session)


def find_eamsapp_ticket_url(session: requests.Session) -> Optional[str]:
    """在已登录统一身份后，获取移动教务登录票据 URL。"""
    service_q = urllib.parse.quote(EAMSAPP_CAS_SERVICE, safe="")
    login_url = f"https://idas.uestc.edu.cn/authserver/login?service={service_q}"
    base_hdr = dict(HEADERS)
    url = login_url
    hdr = dict(base_hdr)
    for _ in range(20):
        r = session.get(url, headers=hdr, allow_redirects=False, timeout=60)
        loc = (r.headers.get("Location") or "").strip()
        if loc:
            loc = urllib.parse.urljoin(str(r.url), loc)
            low = loc.lower()
            if "ticket=" in low and "eamsapp.uestc.edu.cn" in low and "cas-login" in low:
                return loc
        if r.status_code in (301, 302, 303, 307, 308) and loc:
            url = loc
            hdr = dict(base_hdr)
            hdr["Referer"] = str(r.url)
            continue
        final = r.url or ""
        if "ticket=" in final.lower() and "eamsapp" in final.lower():
            return final
        break
    return None


def establish_eamsapp_session_via_cas(
    session: Optional[requests.Session] = None,
) -> Tuple[requests.Session, str]:
    os.environ["UESTC_CAS_SERVICE"] = EAMSAPP_CAS_SERVICE
    sess = session or requests.Session()
    user, pwd = read_login_credentials()
    cas_login(sess, user, pwd)
    jwt = _pick_jwt_jsessionid_from_session(sess)
    if jwt:
        ck = compose_eamsapp_session_cookie(sess, jwt)
        return sess, ck
    ticket_url = find_eamsapp_ticket_url(sess)
    if not ticket_url:
        print("❌ 登录失败，请检查账号密码后重试。", file=sys.stderr)
        sys.exit(1)
    jwt = consume_eamsapp_cas_ticket(sess, ticket_url)
    if not jwt:
        print("❌ 登录失败，未能建立有效会话。", file=sys.stderr)
        sys.exit(1)
    ck = compose_eamsapp_session_cookie(sess, jwt)
    return sess, ck


def jar_mobile_cookie_header_optional(sess: requests.Session) -> Optional[str]:
    """从 Cookie 罐拼装请求头 Cookie。"""
    js = _pick_best_jsessionid_from_jar(sess)
    if not js:
        return None
    vj = _pick_vjuid_from_jar(sess)
    if not vj and _debug_stderr_enabled():
        print("⚠️ 登录 Cookie 不完整，将仅携带会话编号尝试连接。", file=sys.stderr)
    return format_mobile_cookie_header(
        jsessionid=js,
        vjuid=vj,
        extras=_optional_analytics_cookies_from_jar(sess),
    )


def cookie_header_from_requests_session(sess: requests.Session) -> str:
    """从会话 Cookie 罐拼装请求头。"""
    hdr = jar_mobile_cookie_header_optional(sess)
    if hdr:
        return hdr
    print(
        "会话里没有可用的 JSESSIONID（移动 API 令牌）。"
        "请完成统一身份登录，或删除 session_cookies.json 后重试。",
        file=sys.stderr,
    )
    sys.exit(1)


def parse_cookie_header_value(cookie_header: str, name: str) -> Optional[str]:
    target = name.strip()
    if not target or not (cookie_header or "").strip():
        return None
    for part in cookie_header.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        if k.strip() == target:
            return v.strip()
    return None


def emit_session_status(*, from_snapshot: bool = False, pasted: bool = False) -> None:
    """向用户打印登录状态（简短中文）。"""
    if from_snapshot:
        print(f"✅ 已使用 {COOKIE_SNAPSHOT_FILENAME} 中的登录状态", flush=True)
    elif pasted:
        print("✅ 已使用粘贴的 Cookie", flush=True)
    else:
        print(f"✅ 登录成功，已保存到 {COOKIE_SNAPSHOT_FILENAME}", flush=True)


def _login_success_msg_debug_only() -> None:
    if DEBUG_VERBOSE:
        print("✅ 登录成功", flush=True)


def blade_auth_bearer_from_cookie(cookie_hdr: str) -> str:
    """从 Cookie 取出 API 授权令牌。"""
    j = parse_cookie_header_value(cookie_hdr, "JSESSIONID") or ""
    if mobile_jessionid_looks_like_jwt(j):
        return j
    tok = os.environ.get("UESTC_EAMSAPP_SESSION_TOKEN", "").strip()
    if mobile_jessionid_looks_like_jwt(tok):
        return tok
    if _debug_stderr_enabled():
        print(
            "⚠️ Cookie 中缺少有效的登录令牌，且未设置备用令牌环境变量；"
            "请重新登录。",
            file=sys.stderr,
        )
    return ""


# -------------------------------------------------------------------------
# 入口：解析 Cookie、选择查询功能
# -------------------------------------------------------------------------

def resolve_cookie_header() -> str:
    snap_path = session_cookies_snapshot_path()
    skip_snap = os.environ.get("UESTC_SKIP_SESSION_SNAPSHOT", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )

    if skip_snap:
        return resolve_cookie_via_portal_session(force_fresh=True)

    if os.path.isfile(snap_path):
        return resolve_cookie_via_portal_session()

    if not sys.stdin.isatty():
        return resolve_cookie_via_portal_session()

    print(
        f"未找到 `{COOKIE_SNAPSHOT_FILENAME}`（当前目录：{Path.cwd()}）。\n"
        "—— **回车**：统一身份登录（成功后写入该文件）\n"
        "—— **1**：粘贴浏览器 Cookie",
        flush=True,
    )
    choice = input("请选择 [默认 登录]: ").strip().lower()
    if choice == "1" or choice in ("paste", "粘贴", "cookie"):
        pasted = input("Cookie:\n>").strip()
        if not pasted:
            print("未提供 Cookie。", file=sys.stderr)
            sys.exit(1)
        emit_session_status(pasted=True)
        return upgrade_cookie_header_via_eamsapp_home_if_needed(pasted)
    return resolve_cookie_via_portal_session()


def headers_home(cookie: str) -> Dict[str, str]:
    ua = (
        os.environ.get("UESTC_EAMSAPP_USER_AGENT", "").strip()
        or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0"
    )
    sch = '"Chromium";v="148", "Microsoft Edge";v="148", "Not/A)Brand";v="99"'
    return {
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Cache-Control": "max-age=0",
        "Connection": "keep-alive",
        "Cookie": cookie,
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": ua,
        "sec-ch-ua": sch,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }


def headers_mobile_api(cookie_hdr: str) -> Dict[str, str]:
    ua = (
        os.environ.get("UESTC_EAMSAPP_USER_AGENT", "").strip()
        or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0"
    )
    sch = '"Chromium";v="148", "Microsoft Edge";v="148", "Not/A)Brand";v="99"'
    jwt = blade_auth_bearer_from_cookie(cookie_hdr)
    return {
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Authorization": f"Basic {_BASIC}",
        "Connection": "keep-alive",
        "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
        "Cookie": cookie_hdr,
        "Referer": f"{BASE}/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": ua,
        "blade-auth": f"bearer {jwt}",
        "sec-ch-ua": sch,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }


def cookie_header_merge_shell_set_cookie(sess: requests.Session, prior_cookie_hdr: str) -> str:
    """合并访问移动教务首页后服务器下发的 Cookie。"""
    js = _pick_best_jsessionid_from_jar(sess) or (parse_cookie_header_value(prior_cookie_hdr, "JSESSIONID") or "")
    vj = _pick_vjuid_from_jar(sess) or (
        parse_cookie_header_value(prior_cookie_hdr, "cookie_vjuid_portal_login") or ""
    )
    if not js:
        return prior_cookie_hdr
    extras = _optional_analytics_cookies_from_jar(sess) or _optional_analytics_from_cookie_header(prior_cookie_hdr)
    return format_mobile_cookie_header(jsessionid=js, vjuid=vj, extras=extras)


def upgrade_cookie_header_via_eamsapp_home_if_needed(cookie_hdr: str) -> str:
    """若 Cookie 里是短会话，先访问移动教务首页换取长令牌。"""
    j0 = parse_cookie_header_value(cookie_hdr, "JSESSIONID") or ""
    if mobile_jessionid_looks_like_jwt(j0):
        return cookie_hdr

    skip = os.environ.get("UESTC_EAMSAPP_SKIP_HOME_WARM", "").strip().lower() in ("1", "true", "yes")
    if skip:
        return cookie_hdr

    sess = requests.Session()
    try:
        resp = sess.get(f"{BASE}/", headers=dict(headers_home(cookie_hdr)), timeout=60)
    except OSError as ex:
        print(f"⚠️ 访问移动教务首页失败，无法升级登录状态：`{ex}`", file=sys.stderr)
        sys.exit(1)

    merged = cookie_header_merge_shell_set_cookie(sess, cookie_hdr)
    # 响应头里可能先出现新的登录令牌
    for c in resp.cookies:
        if c.name == "JSESSIONID" and mobile_jessionid_looks_like_jwt(str(c.value or "")):
            vj = _pick_vjuid_from_jar(sess) or (
                parse_cookie_header_value(cookie_hdr, "cookie_vjuid_portal_login") or ""
            )
            js = str(c.value)
            merged = format_mobile_cookie_header(
                jsessionid=js,
                vjuid=vj,
                extras=_optional_analytics_cookies_from_jar(sess)
                or _optional_analytics_from_cookie_header(cookie_hdr),
            )
            break

    j1 = parse_cookie_header_value(merged, "JSESSIONID") or ""
    if mobile_jessionid_looks_like_jwt(j1):
        if DEBUG_VERBOSE:
            print("ℹ️ 已通过访问移动教务首页完成登录状态升级。", flush=True)
        return merged

    print("⚠️ 登录状态可能无效，查询结果或不完整。", file=sys.stderr)
    return merged


def eamsapp_cookie_from_session_after_warm(session: requests.Session) -> Optional[str]:
    """已有统一身份会话时，换取移动教务 API 令牌。"""
    jwt = _pick_jwt_jsessionid_from_session(session)
    if jwt:
        return compose_eamsapp_session_cookie(session, jwt)
    ticket_url = find_eamsapp_ticket_url(session)
    if ticket_url:
        jwt = consume_eamsapp_cas_ticket(session, ticket_url)
        if jwt:
            return compose_eamsapp_session_cookie(session, jwt)
    return jar_mobile_cookie_header_optional(session)


def resolve_cookie_via_portal_session(*, force_fresh: bool = False, _retried: bool = False) -> str:
    """
    获取访问移动教务 API 所需的 Cookie：
    优先读本地 session_cookies.json；无效则统一身份登录后重新保存。
    登录状态失效时会自动清除快照并重登一次。
    """
    fresh_env = os.environ.get("UESTC_FRESH_LOGIN", "").strip().lower() in ("1", "true", "yes")
    fresh = force_fresh or fresh_env

    cookie_file = _session_cookies_snapshot_path()
    session = requests.Session()

    if not fresh and os.path.isfile(cookie_file):
        try:
            _load_session_cookies_from_file(session, cookie_file)
            ck_snap = eamsapp_cookie_from_session_after_warm(session)
            js_snap = parse_cookie_header_value(ck_snap or "", "JSESSIONID") or ""
            if ck_snap and mobile_jessionid_looks_like_jwt(js_snap):
                if _probe_cookie_header_ok(ck_snap):
                    emit_session_status(from_snapshot=True)
                    return ck_snap
                print(f"⚠️ {COOKIE_SNAPSHOT_FILENAME} 已过期，正在重新登录…", flush=True)
                clear_session_cookies_snapshot()
                session = requests.Session()
            else:
                print(f"⚠️ {COOKIE_SNAPSHOT_FILENAME} 无效，正在重新登录…", flush=True)
        except Exception as ex:
            print(f"⚠️ 无法读取 {COOKIE_SNAPSHOT_FILENAME}，将重新登录。", flush=True)
            if DEBUG_VERBOSE:
                print(f"   详情: {ex}", file=sys.stderr)
            session = requests.Session()

    if force_fresh:
        clear_session_cookies_snapshot()
    session, ck_direct = establish_eamsapp_session_via_cas(session)
    try:
        _save_session_cookies_to_file(session, cookie_file)
    except OSError as ex_s:
        print(f"⚠️ 保存 {COOKIE_SNAPSHOT_FILENAME} 失败: {ex_s}", file=sys.stderr)

    if not _probe_cookie_header_ok(ck_direct):
        if _cookie_retry_disabled() or _retried:
            print("⚠️ 登录后会话仍无效，请删除 session_cookies.json 后重试。", file=sys.stderr)
        else:
            return _relogin_after_stale_snapshot(retried=True)

    emit_session_status()
    return ck_direct


def jwt_claims_from_cookie_jwt(jwt: str) -> Dict[str, Any]:
    parts = jwt.split(".")
    if len(parts) < 2:
        return {}
    b = parts[1]
    pad = "=" * ((4 - len(b) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(b + pad).decode("utf-8", errors="replace")
        return json.loads(raw) if raw.strip().startswith("{") else {}
    except (ValueError, json.JSONDecodeError, OSError):
        return {}


def unwrap_blade_like_root(obj: Any) -> Any:
    if isinstance(obj, dict):
        if "data" in obj and obj["data"] is not None:
            return obj["data"]
        if "records" in obj:
            return obj["records"]
        if "rows" in obj:
            return obj["rows"]
    return obj


def _first_int_between(obj: Any, lo: int, hi: int) -> Optional[int]:
    if isinstance(obj, int):
        return obj if lo <= obj <= hi else None
    if isinstance(obj, str) and obj.strip().lstrip("-").isdigit():
        v = int(obj.strip())
        return v if lo <= v <= hi else None
    if isinstance(obj, dict):
        for k in ("week", "curWeek", "currentWeek", "weekNum", "weekNo", "value", "data"):
            v = obj.get(k)
            x = _first_int_between(v, lo, hi)
            if x is not None:
                return x
        for vv in obj.values():
            x = _first_int_between(vv, lo, hi)
            if x is not None:
                return x
    if isinstance(obj, list):
        for it in obj:
            x = _first_int_between(it, lo, hi)
            if x is not None:
                return x
    return None


def _extract_semester_code_from_any(obj: Any, depth: int = 0) -> Optional[str]:
    if depth > 14:
        return None
    if isinstance(obj, (str, int, float)):
        s = str(obj).strip()
        if s.isdigit() and 5 <= len(s) <= 6:
            return s
        return None
    if isinstance(obj, dict):
        for key in (
            "code",
            "semesterCode",
            "semester_code",
            "xnxq",
            "xnxqh",
            "dqxnxqh",
            "dqXnxq",
            "semesterId",
        ):
            v = obj.get(key)
            hit = _extract_semester_code_from_any(v, depth + 1)
            if hit:
                return hit
        for vv in obj.values():
            hit = _extract_semester_code_from_any(vv, depth + 1)
            if hit:
                return hit
    elif isinstance(obj, list):
        for it in obj:
            hit = _extract_semester_code_from_any(it, depth + 1)
            if hit:
                return hit
    return None


def fetch_eamsapp_semester_cur_week(cookie_hdr: str, semester_code: str) -> Optional[int]:
    url = f"{BASE}/api/ydzc-app/semester/getCurWeek?{urllib.parse.urlencode({'code': semester_code})}"
    r = requests.get(url, headers=headers_mobile_api(cookie_hdr), timeout=60)
    txt = getattr(r, "text", "") or ""
    try:
        data = txt.strip()
        if data.startswith("{") or data.startswith("["):
            return _first_int_between(unwrap_blade_like_root(json.loads(data)), 1, 40)
    except json.JSONDecodeError:
        pass
    if _debug_stderr_enabled():
        print(f"⚠️ getCurWeek 解析失败 HTTP {r.status_code} body[:160]={txt[:160]!r}", file=sys.stderr)
    return None


def fetch_eamsapp_cur_semester_code(cookie_hdr: str) -> Optional[str]:
    url = f"{BASE}/api/ydzc-app/semester/getCurSemester"
    r = requests.get(url, headers=headers_mobile_api(cookie_hdr), timeout=60)
    txt = getattr(r, "text", "") or ""
    try:
        if txt.strip().startswith("{") or txt.strip().startswith("["):
            payload = json.loads(txt.strip())
            return _extract_semester_code_from_any(unwrap_blade_like_root(payload))
    except json.JSONDecodeError:
        pass
    if _debug_stderr_enabled():
        print(f"⚠️ getCurSemester 解析学期编码失败 HTTP {r.status_code}", file=sys.stderr)
    return None


def default_student_table_code(cookie_hdr: str) -> str:
    ex = os.environ.get("UESTC_EAMSAPP_STUDENT_CODE", "").strip()
    if ex:
        return ex
    js = parse_cookie_header_value(cookie_hdr, "JSESSIONID") or ""
    claims = jwt_claims_from_cookie_jwt(js)
    uid = claims.get("user_name") or claims.get("account") or ""
    if isinstance(uid, str) and uid.strip():
        return uid.strip()
    print(
        "无法从当前登录状态解析学号。\n"
        "请使用统一身份登录或粘贴浏览器 Cookie，或设置环境变量 UESTC_EAMSAPP_STUDENT_CODE。",
        file=sys.stderr,
    )
    sys.exit(1)


def resolved_semester_code(cookie_hdr: str) -> str:
    manual = os.environ.get("UESTC_EAMSAPP_SEMESTER", "").strip()
    if manual:
        return manual
    got = fetch_eamsapp_cur_semester_code(cookie_hdr)
    if got:
        if DEBUG_VERBOSE:
            print(f"[调试] getCurSemester → 学期编码={got!r}", file=sys.stderr)
        return got
    if DEBUG_VERBOSE:
        print("⚠️ 未得到有效学期编码，沿用默认值。", file=sys.stderr)
    return "25262"


def default_week(cookie_hdr: str, semester_code: str) -> str:
    w = os.environ.get("UESTC_EAMSAPP_WEEK", "").strip()
    if w:
        return w
    cur = fetch_eamsapp_semester_cur_week(cookie_hdr, semester_code)
    if cur is not None:
        if DEBUG_VERBOSE:
            print(f"[调试] getCurWeek → week={cur}", file=sys.stderr)
        return str(cur)
    if DEBUG_VERBOSE:
        print("⚠️ 未得到有效周次，沿用默认值。", file=sys.stderr)
    return "12"


def _student_week_table_url(cookie_hdr: str) -> str:
    semester = resolved_semester_code(cookie_hdr)
    code = default_student_table_code(cookie_hdr)
    week = default_week(cookie_hdr, semester)
    q = urllib.parse.urlencode({"semester": semester, "code": code, "week": week})
    return f"{BASE}/api/ydzc-app/studentCourseTable/week?{q}"


def _grade_student_url(cookie_hdr: str) -> str:
    code = default_student_table_code(cookie_hdr)
    grade_type = os.environ.get("UESTC_EAMSAPP_GRADE_TYPE", "1").strip()
    course_type = os.environ.get("UESTC_EAMSAPP_GRADE_COURSE_TYPE", "").strip()
    passed = os.environ.get("UESTC_EAMSAPP_GRADE_PASSED", "").strip()
    course_name = os.environ.get("UESTC_EAMSAPP_GRADE_COURSE_NAME", "").strip()
    q = urllib.parse.urlencode(
        {
            "code": code,
            "gradeType": grade_type,
            "courseTypeCode": course_type,
            "passed": passed,
            "courseName": course_name,
        },
        quote_via=urllib.parse.quote,
    )
    return f"{BASE}/api/ydzc-app/grade/student?{q}"


def _course_type_list_url() -> str:
    return f"{BASE}/api/ydzc-app/courseType/list"


def _exam_type_url() -> str:
    return f"{BASE}/api/ydzc-app/examTake/examType"


def _exam_take_query_url(cookie_hdr: str) -> str:
    semester = resolved_semester_code(cookie_hdr)
    exam_type_id = os.environ.get("UESTC_EAMSAPP_EXAM_TYPE_ID", "1").strip()
    q = urllib.parse.urlencode({"semester": semester, "examTypeId": exam_type_id})
    return f"{BASE}/api/ydzc-app/examTake/query?{q}"


def _get_cur_semester_url() -> str:
    return f"{BASE}/api/ydzc-app/semester/getCurSemester"


# -------------------------------------------------------------------------
# 课表 / 成绩 / 考试：请求接口并输出 JSON
# -------------------------------------------------------------------------

def _api_json_from_response(r: requests.Response) -> Any:
    """解析接口 JSON，提取 data 等业务字段。"""
    txt = (getattr(r, "text", "") or "").strip()
    if r.status_code >= 400:
        err: Dict[str, Any] = {"error": True, "httpStatus": r.status_code}
        if txt:
            try:
                err["body"] = json.loads(txt)
            except json.JSONDecodeError:
                err["message"] = txt[:500]
        return err
    if not txt:
        return None
    try:
        obj = json.loads(txt)
    except json.JSONDecodeError:
        return {"error": True, "message": txt[:500]}
    if isinstance(obj, dict) and obj.get("success") is False:
        return obj
    return unwrap_blade_like_root(obj)


def _fetch_api(ck: str, url: str) -> requests.Response:
    return requests.get(url, headers=headers_mobile_api(ck), timeout=60)


def _json_indent() -> int:
    compact = os.environ.get("PRETTY_JSON", "1").strip().lower() in ("0", "false", "no", "off")
    return 0 if compact else 2


def _print_json(obj: Any) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=_json_indent()))


def _save_result_json(mode: str, obj: Any) -> str:
    """将查询结果写入当前目录 JSON 文件，返回文件名。"""
    filename = OUTPUT_JSON_FILES.get(mode, f"{mode}.json")
    path = Path.cwd() / filename
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return filename


def _emit_result(mode: str, payload: Any) -> None:
    _print_json(payload)
    name = _save_result_json(mode, payload)
    print(f"已保存到 {name}", file=sys.stderr)


def _collect_timetable(ck: str) -> Tuple[List[requests.Response], Any]:
    r = _fetch_api(ck, _student_week_table_url(ck))
    return [r], _api_json_from_response(r)


def _collect_grades(ck: str) -> Tuple[List[requests.Response], Dict[str, Any]]:
    r_types = _fetch_api(ck, _course_type_list_url())
    r_grades = _fetch_api(ck, _grade_student_url(ck))
    return [r_types, r_grades], {
        "课程类型": _api_json_from_response(r_types),
        "成绩": _api_json_from_response(r_grades),
    }


def _collect_exam(ck: str) -> Tuple[List[requests.Response], Dict[str, Any]]:
    r_sem = _fetch_api(ck, _get_cur_semester_url())
    r_types = _fetch_api(ck, _exam_type_url())
    r_query = _fetch_api(ck, _exam_take_query_url(ck))
    return [r_sem, r_types, r_query], {
        "当前学期": _api_json_from_response(r_sem),
        "考试类型": _api_json_from_response(r_types),
        "考试安排": _api_json_from_response(r_query),
    }


def _responses_auth_failed(responses: List[requests.Response]) -> bool:
    return any(_blade_api_response_auth_failed(r) for r in responses)


def _run_mode(mode: str, ck: str) -> Tuple[str, List[requests.Response]]:
    responses: List[requests.Response] = []
    payload: Any = None

    if mode == "timetable":
        responses, payload = _collect_timetable(ck)
    elif mode == "grades":
        responses, payload = _collect_grades(ck)
    elif mode == "exam":
        responses, payload = _collect_exam(ck)
    elif mode == "all":
        rs, timetable = _collect_timetable(ck)
        responses.extend(rs)
        rs, grades = _collect_grades(ck)
        responses.extend(rs)
        rs, exam = _collect_exam(ck)
        responses.extend(rs)
        payload = {"课表": timetable, **grades, **exam}
    else:
        return ck, responses

    _emit_result(mode, payload)
    return ck, responses


_NORMALIZE_ALIAS = {
    "timetable": "timetable",
    "schedule": "timetable",
    "week": "timetable",
    "kb": "timetable",
    "课表": "timetable",
    "1": "timetable",
    "grades": "grades",
    "grade": "grades",
    "cj": "grades",
    "成绩": "grades",
    "2": "grades",
    "exam": "exam",
    "examtake": "exam",
    "ks": "exam",
    "考试": "exam",
    "3": "exam",
    "all": "all",
    "全部": "all",
    "4": "all",
}


def normalize_mode(raw: Optional[str]) -> str:
    s = (raw or "").strip().lower()
    env = (os.environ.get("UESTC_EAMSAPP_MODE", "") or "").strip().lower()
    if not s and env:
        s = env
    if not s:
        return ""
    return _NORMALIZE_ALIAS.get(s, _NORMALIZE_ALIAS.get(s.lower(), s))


def prompt_mode_interactive() -> str:
    print(
        "\n请选择：\n"
        "  1 — 课表\n"
        "  2 — 成绩\n"
        "  3 — 考试\n"
        "  4 — 全部\n",
        flush=True,
    )
    choice = input("序号（可直接输入中文名，默认 1）: ").strip() or "1"
    mode = normalize_mode(choice)
    if mode not in {"timetable", "grades", "exam", "all"}:
        print(f"无法识别选项 {choice!r}。", file=sys.stderr)
        sys.exit(2)
    return mode


def resolve_mode() -> str:
    if sys.stdin.isatty():
        return prompt_mode_interactive()

    env_mode = normalize_mode(os.environ.get("UESTC_EAMSAPP_MODE"))
    if env_mode and env_mode not in {"timetable", "grades", "exam", "all"}:
        env_mode = ""

    if env_mode in {"timetable", "grades", "exam", "all"}:
        return env_mode
    print("非交互终端请设置 UESTC_EAMSAPP_MODE（或用中文：课表/成绩/考试/全部）。", file=sys.stderr)
    sys.exit(2)


# -------------------------------------------------------------------------
# 程序入口
# -------------------------------------------------------------------------

def main() -> int:
    mode = resolve_mode()
    ck = resolve_cookie_header()
    ck, responses = _run_mode(mode, ck)

    if _responses_auth_failed(responses) and not _cookie_retry_disabled():
        ck = _relogin_after_stale_snapshot(retried=True)
        _run_mode(mode, ck)

    return 0


_headers_student_week = headers_mobile_api


def _session_token_from_env_only() -> str:
    t = os.environ.get("UESTC_EAMSAPP_SESSION_TOKEN", "").strip()
    return t if mobile_jessionid_looks_like_jwt(t) else ""


_session_jwt = _session_token_from_env_only
_cookie_header = resolve_cookie_header
_parse_cookie_header_value = parse_cookie_header_value

if __name__ == "__main__":
    raise SystemExit(main())
