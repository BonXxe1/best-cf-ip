#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""聚合公开优选 IP / 域名，去重后按国家输出。

链接规则：
- 普通 URL 直接抓取。URL 上的 ?port=8443 只在「这一行自己没写端口」时生效，不覆盖已有端口。
- 不以 http:// 或 https:// 开头的值，当成要直接写入的域名或 IP。
- 分组源用 {cc} 占位，文件名大小写用 cc / CC 区分。
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# ============================================================
# 配置
# ============================================================

# 普通源。?port= 是本地默认端口，请求前会去掉。
SOURCES: Dict[str, str] = {
    # 测速优选
    "gaoji_best": "https://ips.gaoji.uk/best_ips.txt",
    "gaoji_full": "https://ips.gaoji.uk/full_ips.txt",
    "svip_best": "https://raw.githubusercontent.com/svip-s/cloudflare_ip/refs/heads/main/best_ips.txt",
    "svip_domain": "https://raw.githubusercontent.com/svip-s/cloudflare_ip/refs/heads/main/domain.txt",
    "mjz_best": "https://cf.junzhen.qzz.io/best_ips.txt",
    "mjz_bj": "https://cf.junzhen.qzz.io/best_ips_bj.txt",
    "loveztm_best": "https://raw.githubusercontent.com/love-ztm/cfip/refs/heads/main/best_ips.txt",
    "loveztm_ubest": "https://raw.githubusercontent.com/love-ztm/cfip/refs/heads/main/ubest_ips.txt",
    # 聚合
    "lancelot_ips": "https://raw.githubusercontent.com/LancelotRar/best-cf-ips/main/best-cf-ip-collected.txt",
    "lancelot_top100": "https://raw.githubusercontent.com/LancelotRar/best-cf-ips/main/best-cf-ip-scanned-top100.txt",
    "lancelot_domains": "https://raw.githubusercontent.com/LancelotRar/best-cf-domains/main/best-cf-domain.txt",
    "joname_v4": "https://raw.githubusercontent.com/joname1/BestCFip/refs/heads/main/ipv4.txt",
    "joname_v6": "https://raw.githubusercontent.com/joname1/BestCFip/refs/heads/main/ipv6.txt",
    "senflare": "https://raw.githubusercontent.com/Senflare/Senflare-IP/refs/heads/main/Senflare-Pro.txt",
    "shark_addip": "https://raw.githubusercontent.com/shark0816/addresses/refs/heads/main/addip.txt",
    "leilaomi": "https://bestip.leilaomi.cc.cd/ips.txt",
    "yuanxiawan": "https://raw.githubusercontent.com/yuanxiawan/cfipv4db/refs/heads/main/cfip.txt",
    "einsitang": "https://raw.githubusercontent.com/einsitang/my-fast-cf-ip/refs/heads/master/fastips.txt",
    "hubbylei": "https://raw.githubusercontent.com/hubbylei/bestcf/refs/heads/main/bestcf.txt",
    "jiechao": "https://raw.githubusercontent.com/JieChaoCC/cf-ip-auto/refs/heads/main/data/ipapi.txt",
    "ahang": "https://raw.githubusercontent.com/ahang39/router/refs/heads/main/all.txt",
    # IPDB
    "ipdb_bestcf_v4": "https://raw.githubusercontent.com/ymyuuu/IPDB/refs/heads/main/BestCF/bestcfv4.txt?port=443",
    "ipdb_bestcf_v6": "https://raw.githubusercontent.com/ymyuuu/IPDB/refs/heads/main/BestCF/bestcfv6.txt?port=443",
    "ipdb_bestproxy": "https://raw.githubusercontent.com/ymyuuu/IPDB/refs/heads/main/BestProxy/bestproxy%26country.txt?port=443",
    "ipdb_api_proxy": "https://ipdb.api.030101.xyz/?type=bestproxy&country=true",
    # CMLiussss / cmliu
    "cmliu": "https://raw.githubusercontent.com/cmliu/WorkerVless2sub/main/addressesapi.txt",
    "coolapk": "https://raw.githubusercontent.com/Coolapk-Code9527/Cloudflare-IP/main/ip.txt?port=443",
    "090227_ct": "https://addressesapi.090227.xyz/ct?port=443",
    "090227_cmcc": "https://addressesapi.090227.xyz/cmcc?port=443",
    "090227_cfyes": "https://addressesapi.090227.xyz/CloudFlareYes?port=443",
    "cf090227_ct": "https://cf.090227.xyz/ct",
    "cf090227_cu": "https://cf.090227.xyz/cu",
    "cf090227_cmcc": "https://cf.090227.xyz/cmcc",
    # bestcf.pages.dev 镜像（国家分包的见 GROUPED_SOURCES）
    "bestcf_uouin": "https://bestcf.pages.dev/uouin/all.txt",
    "bestcf_wetest": "https://bestcf.pages.dev/wetest/ipv4.txt",
    "bestcf_cfyes_v4": "https://bestcf.pages.dev/cfyes/ipv4.txt",
    "bestcf_cfyes_v6": "https://bestcf.pages.dev/cfyes/ipv6.txt",
    "bestcf_mia": "https://bestcf.pages.dev/xinyitang3/ipv4.txt",
    "bestcf_luoli": "https://bestcf.pages.dev/luoli/all.txt",
    "bestcf_cmliu": "https://bestcf.pages.dev/cmliu/all.txt",
    "bestcf_vvhan_v4": "https://bestcf.pages.dev/vvhan/ipv4.txt",
    "bestcf_vvhan_v6": "https://bestcf.pages.dev/vvhan/ipv6.txt",
    "bestcf_nirevil_v4": "https://bestcf.pages.dev/nirevil/ipv4.txt",
    "bestcf_nirevil_v6": "https://bestcf.pages.dev/nirevil/ipv6.txt",
    "bestcf_lzj": "https://bestcf.pages.dev/lzj/all.txt",
    "bestcf_ircf_ip": "https://bestcf.pages.dev/ircf/ipv4.txt",
    "bestcf_tiancheng_all": "https://bestcf.pages.dev/tiancheng/all.txt",
    "bestcf_s5gy_all": "https://bestcf.pages.dev/s5gy/all.txt",
    "bestcf_domain_mini": "https://bestcf.pages.dev/domain/mini.txt?port=443",
    "bestcf_domain_all": "https://bestcf.pages.dev/domain/all.txt?port=443",
    "bestcf_domain_asia": "https://bestcf.pages.dev/domain/Domain-Asia.txt?port=443",
    "bestcf_domain_ai": "https://bestcf.pages.dev/domain/Domain-AI-VPS789.txt?port=443",
    "bestcf_domain_ygkkk": "https://bestcf.pages.dev/domain/ygkkk/all.txt?port=443",
    "bestcf_domain_qms": "https://bestcf.pages.dev/domain/qms/all.txt?port=443",
    "bestcf_domain_fiatnorm": "https://bestcf.pages.dev/domain/fiatnorm/all.txt?port=443",
    "bestcf_domain_senflare": "https://bestcf.pages.dev/domain/senflare/all.txt?port=443",
    "bestcf_domain_wuya": "https://bestcf.pages.dev/domain/wuya/all.txt?port=443",
    "bestcf_domain_ircf": "https://bestcf.pages.dev/domain/ircf/all.txt?port=443",
    "bestcf_vps789_top10": "https://bestcf.pages.dev/vps789/top10.txt",
    "bestcf_vps789_top20": "https://bestcf.pages.dev/vps789/top20.txt",
    "bestcf_vps789_top50": "https://bestcf.pages.dev/vps789/top50.txt",
    "bestcf_vps789_top100": "https://bestcf.pages.dev/vps789/top100.txt",
    "bestcf_tiancheng_mini": "https://bestcf.pages.dev/tiancheng/mini.txt",
    "bestcf_tiancheng2_all": "https://bestcf.pages.dev/tiancheng2/all.txt",
    "bestcf_tiancheng2_mini": "https://bestcf.pages.dev/tiancheng2/mini.txt",
    "bestcf_tiancheng3_all": "https://bestcf.pages.dev/tiancheng3/all.txt",
    "bestcf_tiancheng3_mini": "https://bestcf.pages.dev/tiancheng3/mini.txt",
    "bestcf_gslege_cfxyz": "https://bestcf.pages.dev/gslege/Cfxyz.txt",
    "bestcf_zhixuan": "https://bestcf.pages.dev/zhixuanwang/ipv4-onlyip.txt?port=443",
    "bestcf_s5gy_mini": "https://bestcf.pages.dev/s5gy/mini.txt",
    "bestcf_cmliu2": "https://bestcf.pages.dev/cmliu2/all.txt",
    "bestcf_kristi": "https://bestcf.pages.dev/kristi/all.txt",
    "bestcf_moistr": "https://bestcf.pages.dev/moistr/all.txt",
    "bestcf_yutian": "https://bestcf.pages.dev/yutian/all.txt",
    "bestcf_warp": "https://bestcf.pages.dev/WARP/WARP-MINI.txt",
    "bestcf_warp_443": "https://bestcf.pages.dev/WARP/WARP-MINI-443.txt",
    "bestcf_warp_8443": "https://bestcf.pages.dev/WARP/WARP-MINI-8443.txt",
    "bestcf_entryip": "https://bestcf.pages.dev/entryip/50.txt",
    "bestcf_090227_all": "https://090227.pages.dev/bestcf?isp=all&ips=20",
    "bestcf_090227_ct": "https://090227.pages.dev/bestcf?isp=ct&ips=50",
    "bestcf_090227_cu": "https://090227.pages.dev/bestcf?isp=cu&ips=50",
    "bestcf_090227_cmcc": "https://090227.pages.dev/bestcf?isp=cmcc&ips=50",
    "090227_ip164746": "https://addressesapi.090227.xyz/ip.164746.xyz?port=443",
    "lancelot_top400": "https://raw.githubusercontent.com/LancelotRar/best-cf-ips/refs/heads/main/best-cf-ip-scanned-top400.txt",
    "gshtwy_wetest": "https://raw.githubusercontent.com/gshtwy/CF-DNS-Clone/refs/heads/main/wetest-cloudflare-v4.txt",
    "fiatnorm_ips": "https://raw.githubusercontent.com/Fiatnorm/OptiDomain-Pages/refs/heads/main/optimized_cf_ips.txt",
    "zip_cm": "https://zip.cm.edu.kg/all.txt",
    "countrymerge": "https://countrymerge.pages.dev/all.txt",
    "xgonce_csv": "https://raw.githubusercontent.com/xgonce/Cloudflare_IP/refs/heads/main/result.csv",
    "proxyip_ltd": "https://github.com/Xiaobei09/proxyip/raw/refs/heads/main/data/valid/all_ltd.txt",
    "kafemars_domains": "https://raw.githubusercontent.com/KafeMars/best-ips-domains/main/BestDomains",
    # 直接写入，不发起请求
    "literal_cm": "Cm.Soso.Edu.Kg",
    "literal_sub": "Sub.Cmliussss.Net",
    "literal_owo": "Owo.O00o.Ooo",
}

# 模板, 国家码, 路径里用小写还是大写
GROUPED_SOURCES = [
    (
        "proxifly",
        "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/countries/{cc}/data.txt",
        ["HK", "TW", "US", "SG", "JP", "KR", "NL", "DE"],
        True,
    ),
    (
        "gslege",
        "https://raw.githubusercontent.com/gslege/CloudflareIP/refs/heads/main/{cc}.txt",
        ["US", "JP", "SG", "DE", "NL"],
        True,
    ),
    (
        "tiancheng",
        "https://bestcf.pages.dev/tiancheng/{cc}.txt",
        ["HK", "SG", "JP", "KR", "US", "TW"],
        False,
    ),
    (
        "tiancheng2",
        "https://bestcf.pages.dev/tiancheng2/{cc}.txt",
        ["HK", "DE", "JP", "KR", "SG", "US", "TW"],
        False,
    ),
    (
        "tiancheng3",
        "https://bestcf.pages.dev/tiancheng3/{cc}.txt",
        ["HK", "SG", "JP", "KR", "US", "TW"],
        False,
    ),
    (
        "s5gy",
        "https://bestcf.pages.dev/s5gy/{cc}.txt",
        ["HK", "SG", "JP", "KR", "US", "TW"],
        False,
    ),
    (
        "bestcf_gslege",
        "https://bestcf.pages.dev/gslege/{cc}.txt",
        ["SG", "DE", "US", "NL", "JP"],
        True,
    ),
    (
        "kafemars",
        "https://raw.githubusercontent.com/KafeMars/best-ips-domains/main/CF-BestIPs-{cc}",
        ["HK", "JP", "SG", "US"],
        True,
    ),
]

ALLOWED_PORTS = {
    "443", "8443", "2053", "2083", "2087", "2096",
    "80", "8080", "3128", "1080", "8888", "8880",
    "2052", "2082", "2086", "2095", "10808", "10809",
    "7443", "4443",
}
ORDER = ["HK", "SG", "JP", "KR", "TW", "US", "DE", "NL", "AE", "GB", "CF"]
OUTPUT_FILE = "best_ips_grouped_full.txt"
DEFAULT_PORT = "443"
WORKERS = 10
FETCH_TIMEOUT = 15
MAX_BYTES = 2_000_000

# ============================================================
# 国家 / 机场码
# ============================================================

CC_SET = set(
    """
    AD AE AF AG AI AL AM AO AR AT AU AZ BA BB BD BE BF BG BH BI BJ BN BO BR BS BT BW BY BZ
    CA CD CG CH CI CL CN CO CR CV CY CZ DE DJ DK DM DO DZ EC EE EG ER ES ET FI FJ FM
    FR GA GB GD GE GH GM GN GQ GR GT GW GY HN HR HT HU ID IE IL IN IQ IR IS IT JM JO JP KE
    KG KH KI KM KN KP KR KW KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MG MH MK ML MM
    MN MR MT MU MV MW MX MY MZ NA NE NG NI NL NO NP NR NZ OM PA PE PG PH PK PL PS PT PW PY
    QA RO RS RW SA SB SC SD SE SG SI SK SL SM SN SO SR SS ST SV SY SZ TD TG TH TJ TL TM TN
    TO TR TT TZ UA UG US UY UZ VA VC VE VN VU WS YE ZA ZM ZW HK MO TW
    """.split()
)

# CT/CU/CM 在这些列表里是运营商，不是国家。CU/CM 不放进 CC_SET。
ISP_PREFIX = (
    ("CMCC", "移动"),
    ("CUCC", "联通"),
    ("CTCC", "电信"),
    ("CM", "移动"),
    ("CU", "联通"),
    ("CT", "电信"),
)

COLO = {
    "HKG": "HK", "MFM": "MO", "SIN": "SG",
    "NRT": "JP", "HND": "JP", "KIX": "JP", "FUK": "JP", "OKA": "JP",
    "ICN": "KR", "GMP": "KR", "TPE": "TW", "KHH": "TW",
    "LAX": "US", "SJC": "US", "SFO": "US", "SEA": "US", "DFW": "US", "ORD": "US",
    "IAD": "US", "EWR": "US", "ATL": "US", "MIA": "US", "DEN": "US", "PHX": "US",
    "BOS": "US", "SLC": "US", "LAS": "US", "MCI": "US", "MSP": "US", "DTW": "US",
    "CLT": "US", "IAH": "US", "PDX": "US", "SAN": "US", "AUS": "US", "BNA": "US",
    "RDU": "US", "PHL": "US", "CLE": "US", "PIT": "US",
    "FRA": "DE", "MUC": "DE", "BER": "DE", "DUS": "DE", "HAM": "DE", "STR": "DE", "TXL": "DE",
    "AMS": "NL", "LHR": "GB", "MAN": "GB", "LCY": "GB", "EDI": "GB",
    "CDG": "FR", "MRS": "FR", "ORY": "FR",
    "DXB": "AE", "AUH": "AE", "SYD": "AU", "MEL": "AU", "BNE": "AU", "PER": "AU",
    "BOM": "IN", "DEL": "IN", "MAA": "IN", "BLR": "IN", "HYD": "IN",
    "GRU": "BR", "GIG": "BR", "YYZ": "CA", "YVR": "CA", "YUL": "CA",
    "ARN": "SE", "MXP": "IT", "FCO": "IT", "MAD": "ES", "BCN": "ES",
    "WAW": "PL", "VIE": "AT", "ZRH": "CH", "GVA": "CH", "CPH": "DK", "HEL": "FI", "OSL": "NO",
    "IST": "TR", "LIS": "PT", "PRG": "CZ", "BUD": "HU", "ATH": "GR", "TLV": "IL",
    "BKK": "TH", "KUL": "MY", "CGK": "ID", "MNL": "PH", "SGN": "VN", "HAN": "VN",
    "JNB": "ZA", "CPT": "ZA", "EZE": "AR", "SCL": "CL", "BOG": "CO", "MEX": "MX", "LIM": "PE",
    "AKL": "NZ", "DME": "RU", "LED": "RU", "IEV": "UA", "KBP": "UA",
    "DOH": "QA", "BAH": "BH", "KWI": "KW", "RUH": "SA", "JED": "SA", "CAI": "EG",
    "DUB": "IE", "BRU": "BE", "LUX": "LU", "OTP": "RO", "SOF": "BG", "BEG": "RS",
}

EN_NAMES = sorted(
    [
        ("united states", "US"), ("united kingdom", "GB"), ("hong kong", "HK"),
        ("hongkong", "HK"), ("singapore", "SG"), ("netherlands", "NL"),
        ("germany", "DE"), ("australia", "AU"), ("canada", "CA"), ("japan", "JP"),
        ("korea", "KR"), ("taiwan", "TW"), ("france", "FR"), ("india", "IN"),
        ("brazil", "BR"), ("turkey", "TR"), ("vietnam", "VN"), ("malaysia", "MY"),
        ("indonesia", "ID"), ("philippines", "PH"), ("thailand", "TH"),
        ("russia", "RU"), ("italy", "IT"), ("spain", "ES"), ("switzerland", "CH"),
        ("sweden", "SE"), ("poland", "PL"), ("macau", "MO"), ("macao", "MO"),
        ("america", "US"), ("britain", "GB"),
    ],
    key=lambda item: -len(item[0]),
)

CN_NAMES = sorted(
    [
        ("香港", "HK"), ("台湾", "TW"), ("台灣", "TW"), ("日本", "JP"),
        ("新加坡", "SG"), ("韩国", "KR"), ("韓國", "KR"), ("美国", "US"), ("美國", "US"),
        ("德国", "DE"), ("德國", "DE"), ("荷兰", "NL"), ("荷蘭", "NL"),
        ("英国", "GB"), ("英國", "GB"), ("法国", "FR"), ("法國", "FR"),
        ("澳大利亚", "AU"), ("澳洲", "AU"), ("加拿大", "CA"),
        ("阿联酋", "AE"), ("阿聯酋", "AE"), ("俄罗斯", "RU"), ("俄羅斯", "RU"),
        ("巴西", "BR"), ("土耳其", "TR"), ("泰国", "TH"), ("泰國", "TH"),
        ("越南", "VN"), ("马来西亚", "MY"), ("馬來西亞", "MY"),
        ("印度尼西亚", "ID"), ("印尼", "ID"), ("菲律宾", "PH"), ("菲律賓", "PH"),
        ("澳门", "MO"), ("澳門", "MO"), ("意大利", "IT"), ("西班牙", "ES"),
        ("瑞士", "CH"), ("瑞典", "SE"), ("印度", "IN"),
    ],
    key=lambda item: -len(item[0]),
)

TOKEN_RE = re.compile(
    r"(?:(?:socks5|socks4|https?)://)?"
    r"(?:"
    r"\[[0-9A-Fa-f:]+\]"
    r"|(?:\d{1,3}\.){3}\d{1,3}"
    r"|(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f:]*"
    r"|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}"
    r")"
    r"(?::\d{1,5})?"
    r"(?:#[^\s]+)?",
    re.I,
)
SCHEME_RE = re.compile(r"^(?:socks5|socks4|https?)://", re.I)
DOMAIN_RE = re.compile(
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}"
)

Entry = Tuple[str, str, str, str, bool]  # host, port, cc, region, is_isp


def log(msg: str) -> None:
    print(msg, flush=True)


def split_url_port(url: str) -> Tuple[str, str]:
    parts = urlsplit(url)
    port = ""
    kept = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key == "port" and value in ALLOWED_PORTS:
            port = value
        else:
            kept.append((key, value))
    clean = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(kept), ""))
    return clean, port


def fetch(url: str) -> str:
    last_err: Optional[BaseException] = None
    for _ in range(2):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
                raw = resp.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raw = raw[:MAX_BYTES]
            text = raw.decode("utf-8", errors="ignore").lstrip("\ufeff")
            head = text[:240].lower()
            if "<html" in head or "<!doctype" in head:
                return ""
            return text
        except Exception as exc:  # noqa: BLE001 - 网络失败要吃掉并重试
            last_err = exc
            time.sleep(0.4)
    raise RuntimeError(str(last_err) if last_err else "fetch failed")


def is_public_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(ip.is_global)


def valid_domain(host: str) -> bool:
    if len(host) > 253 or ".." in host or host.startswith("-"):
        return False
    lowered = host.lower()
    if "updated" in lowered or lowered.startswith(("ipv4.", "ipv6.")):
        return False
    return bool(DOMAIN_RE.fullmatch(host))


def canonical_host(host: str) -> Optional[str]:
    host = host.strip().strip("[]")
    if not host:
        return None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if valid_domain(host):
            return host
        return None
    if not ip.is_global:
        return None
    if isinstance(ip, ipaddress.IPv6Address):
        return ip.compressed.lower()
    return str(ip)


def format_host(host: str) -> str:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host
    if isinstance(ip, ipaddress.IPv6Address):
        return f"[{ip.compressed.lower()}]"
    return str(ip)


def extract_meta(remark: str, default_cc: str) -> Tuple[str, str, bool]:
    remark = remark.strip()
    isp = ""
    cc = ""
    if remark:
        token = re.split(r"[\s|/]+", remark, maxsplit=1)[0]
        upper = token.upper()
        for prefix, name in ISP_PREFIX:
            if upper == prefix or upper.startswith(prefix + "-") or upper.startswith(prefix + "_"):
                isp = name
                break
        if not isp:
            match = re.match(r"^([A-Za-z]{2})(?:$|[^A-Za-z])", token)
            if match:
                cand = match.group(1).upper()
                if cand == "UK":
                    cand = "GB"
                if cand in CC_SET:
                    cc = cand
        if not cc and not isp:
            match = re.match(r"^([A-Za-z]{3})", token)
            if match and match.group(1).upper() in COLO:
                cc = COLO[match.group(1).upper()]
        if not cc and not isp:
            head = remark.lower()
            for name, code in EN_NAMES:
                if head.startswith(name):
                    cc = code
                    break
        if not cc:
            for name, code in CN_NAMES:
                if name in remark:
                    cc = code
                    break
        if not cc and not isp:
            for match in re.finditer(r"(?<![A-Za-z])([A-Z]{2})(?![A-Za-z])", remark):
                cand = "GB" if match.group(1) == "UK" else match.group(1)
                if cand in CC_SET:
                    cc = cand
                    break
        if not cc and not isp:
            for match in re.finditer(r"(?<![A-Za-z])([A-Z]{3})(?![A-Za-z0-9])", remark):
                if match.group(1) in COLO:
                    cc = COLO[match.group(1)]
                    break
        if not isp:
            for word, name in (("电信", "电信"), ("联通", "联通"), ("移动", "移动")):
                if word in remark:
                    isp = name
                    break
    if not cc:
        cc = (default_cc or "CF").upper()
    if cc == "UK":
        cc = "GB"
    return cc, isp, bool(isp)


def split_endpoint(line: str) -> Tuple[str, str, str]:
    body = SCHEME_RE.sub("", line.strip(), count=1)
    remark = ""
    if "#" in body:
        body, remark = body.split("#", 1)
    body = body.strip()
    remark = remark.strip()
    if body.startswith("[") and "]" in body:
        host, rest = body[1:].split("]", 1)
        port = rest[1:] if rest.startswith(":") else ""
        return host, port, remark
    if body.count(":") >= 2:
        return body, "", remark
    if ":" in body:
        host, port = body.rsplit(":", 1)
        if port.isdigit():
            return host, port, remark
    return body, "", remark


def parse_record(
    line: str,
    default_port: str = DEFAULT_PORT,
    default_cc: str = "",
    source_region: str = "",
) -> Optional[Entry]:
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("//") or line.startswith("<"):
        return None
    host_raw, port_raw, remark = split_endpoint(line)
    host = canonical_host(host_raw)
    if not host:
        return None
    if port_raw:
        if not port_raw.isdigit():
            return None
        port = str(int(port_raw))
        if port not in ALLOWED_PORTS:
            return None
    else:
        port = default_port or DEFAULT_PORT
        if port not in ALLOWED_PORTS:
            return None
    cc, region, is_isp = extract_meta(remark, default_cc)
    if not region and source_region:
        region = source_region
    if region:
        region = re.sub(r"\s+", "", region)[:16]
    return host, port, cc, region, is_isp


def iter_records(text: str) -> Iterable[str]:
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#/<!" or line.startswith("//"):
            continue
        if "," in line and not line.lower().startswith("ip,"):
            parts = [part.strip() for part in line.split(",")]
            if (
                len(parts) >= 5
                and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", parts[0])
                and parts[2].isdigit()
            ):
                cc = parts[4].upper()
                yield f"{parts[0]}:{parts[2]}" + (f"#{cc}" if re.fullmatch(r"[A-Z]{2}", cc) else "")
                continue
        if " | " in line:
            yield line
            continue
        found = list(TOKEN_RE.finditer(line))
        if len(found) >= 2:
            for match in found:
                yield match.group(0)
        else:
            yield line


class Collector:
    def __init__(self) -> None:
        self.best: Dict[Tuple[str, str], Entry] = {}
        self._lock = threading.Lock()

    def add(self, item: Entry) -> None:
        host, port, cc, region, is_isp = item
        key = (host.lower(), port)
        with self._lock:
            old = self.best.get(key)
            if old is None or _better(old, item):
                self.best[key] = item

    def lines_by_cc(self) -> Dict[str, List[str]]:
        grouped: Dict[str, List[str]] = defaultdict(list)
        for host, port, cc, region, _is_isp in self.best.values():
            line = f"{format_host(host)}:{port}#{cc}"
            if region:
                line += f"-{region}"
            grouped[cc].append(line)
        for cc, rows in grouped.items():
            rows.sort(key=_line_sort_key)
        return grouped


def _better(old: Entry, new: Entry) -> bool:
    _oh, _op, old_cc, old_region, old_isp = old
    _nh, _np, new_cc, _new_region, new_isp = new
    old_spec = old_cc != "CF"
    new_spec = new_cc != "CF"
    if new_spec != old_spec:
        return new_spec
    if new_isp != old_isp:
        return new_isp
    # 同一国家时，去掉纯来源名标签，保留更干净的一行
    if old_spec and new_spec and old_cc == new_cc and old_region and not _new_region and not old_isp:
        return True
    return False


def _line_sort_key(line: str) -> tuple:
    body = line.split("#", 1)[0]
    if body.startswith("["):
        host, port = body[1:].split("]:", 1)
    else:
        host, port = body.rsplit(":", 1)
    try:
        ip = ipaddress.ip_address(host)
        return (0 if ip.version == 4 else 1, ip.packed, int(port))
    except ValueError:
        return (2, host.lower().encode(), int(port))


def feed_text(
    text: str,
    collector: Collector,
    default_cc: str = "",
    source_region: str = "",
    default_port: str = "",
) -> int:
    count = 0
    for record in iter_records(text):
        parsed = parse_record(
            record,
            default_port=default_port or DEFAULT_PORT,
            default_cc=default_cc,
            source_region=source_region,
        )
        if not parsed:
            continue
        collector.add(parsed)
        count += 1
    return count


Job = Tuple[str, str, str, str, str]  # name, url or "", inline, default_cc, port


def build_jobs() -> List[Job]:
    jobs: List[Job] = []
    seen_url = set()
    for name, raw in SOURCES.items():
        if raw.startswith(("http://", "https://")):
            url, port = split_url_port(raw)
            if url in seen_url:
                continue
            seen_url.add(url)
            jobs.append((name, url, "", "", port))
        else:
            jobs.append((name, "", raw, "", DEFAULT_PORT))
    for name, template, countries, upper in GROUPED_SOURCES:
        for cc in countries:
            path_cc = cc.upper() if upper else cc.lower()
            url = template.format(cc=path_cc)
            if url in seen_url:
                continue
            seen_url.add(url)
            jobs.append((f"{name}/{cc.upper()}", url, "", cc.upper(), ""))
    return jobs


def run_job(job: Job, collector: Collector) -> Tuple[str, int, str]:
    name, url, inline, default_cc, port = job
    try:
        text = inline if not url else fetch(url)
    except Exception as exc:  # noqa: BLE001
        return name, 0, str(exc)
    if not text:
        return name, 0, "空响应"
    region = name.split("/", 1)[0] if "/" in name else ""
    count = feed_text(
        text,
        collector,
        default_cc=default_cc,
        source_region=region,
        default_port=port,
    )
    return name, count, ""


def write_output(collector: Collector) -> List[str]:
    grouped = collector.lines_by_cc()
    lines: List[str] = []
    emitted = set()

    def emit(cc: str) -> None:
        for item in grouped.get(cc, []):
            if item not in emitted:
                emitted.add(item)
                lines.append(item)

    for cc in ORDER:
        emit(cc)
    for cc in sorted(grouped):
        if cc not in ORDER:
            emit(cc)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + ("\n" if lines else ""))
    return lines


def self_check() -> None:
    cases = [
        ("43.164.132.109:443#KR [优选高速 64.85ms 15.7Mbps]", "43.164.132.109", "443", "KR", ""),
        ("108.162.198.8#jp 【日本】 JP", "108.162.198.8", "443", "JP", ""),
        ("[2606:4700::1]:443#IPDBv6-abc", "2606:4700::1", "443", "CF", ""),
        ("162.159.236.194:443#NRT-联通", "162.159.236.194", "443", "JP", "联通"),
        ("198.41.208.74#CM-Default", "198.41.208.74", "443", "CF", "移动"),
        ("104.18.40.100:2096#Canada", "104.18.40.100", "2096", "CA", ""),
        ("socks5://165.154.20.187:10808", "165.154.20.187", "10808", "CF", ""),
        ("shopify.com:443#优选 | shopify.com", "shopify.com", "443", "CF", ""),
        ("Cm.Soso.Edu.Kg", "Cm.Soso.Edu.Kg", "443", "CF", ""),
        ("104.18.33.50#US 美国节点 | 01", "104.18.33.50", "443", "US", ""),
        ("172.64.158.198#HKG", "172.64.158.198", "443", "HK", ""),
        ("104.17.22.231#CF 移动优选", "104.17.22.231", "443", "CF", "移动"),
        ("104.18.85.29#CMCC", "104.18.85.29", "443", "CF", "移动"),
    ]
    for raw, host, port, cc, region in cases:
        got = parse_record(raw)
        assert got is not None, raw
        assert got[0] == host and got[1] == port and got[2] == cc and got[3] == region, (raw, got)
    assert parse_record("104.17.164.774") is None
    assert parse_record("127.0.0.1:443") is None
    assert parse_record("ipv4.list.updated.at#Upd20261020_11:51") is None
    multi = list(iter_records("8.222.219.140#SG 47.57.245.232#HK"))
    assert len(multi) == 2, multi
    kept = list(iter_records("43.175.131.30:443#天诚优选1 | 港岛茶记 | HK | 43.175.131.30:443"))
    assert len(kept) == 1 and parse_record(kept[0])[2] == "HK"
    url, port = split_url_port("https://example.com/a.txt?port=8443&x=1")
    assert url == "https://example.com/a.txt?x=1" and port == "8443"


def main() -> None:
    self_check()
    started = time.time()
    collector = Collector()
    jobs = build_jobs()
    stats: Dict[str, Tuple[int, str]] = {}
    log(f"[开始] {len(jobs)} 个源，并发 {WORKERS}")
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(run_job, job, collector): job[0] for job in jobs}
        for future in as_completed(futures):
            name, count, err = future.result()
            stats[name] = (count, err)
            if err:
                log(f"[失败] {name}: {err}")
            else:
                log(f"[完成] {name}: {count} 条")
    lines = write_output(collector)
    hit = sum(count for count, err in stats.values() if not err)
    failed = sorted(name for name, (_c, err) in stats.items() if err)
    log("---- 命中 ----")
    for name, (count, err) in sorted(stats.items()):
        if count:
            log(f"  {name}: {count}")
    log(f"解析命中: {hit}")
    log(f"去重后: {len(lines)} -> {OUTPUT_FILE}")
    log(f"失败 {len(failed)} 个" + (f": {', '.join(failed)}" if failed else ""))
    log(f"用时 {time.time() - started:.1f}s")


if __name__ == "__main__":
    main()
