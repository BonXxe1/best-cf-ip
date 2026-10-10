import re
import urllib.request
from collections import defaultdict
from typing import Dict, List

# ============================================================
# 配置区
# ============================================================

# ---- 普通源：只需填 URL，格式自动识别 ----
SOURCES: Dict[str, str] = {
    "gaoji":            "https://ips.gaoji.uk/best_ips.txt?port=443",
    "gaoji_full":       "https://ips.gaoji.uk/full_ips.txt",
    "lancelot_ips":     "https://raw.githubusercontent.com/LancelotRar/best-cf-ips/main/best-cf-ip-collected.txt?port=443",
    "lancelot_domains": "https://raw.githubusercontent.com/LancelotRar/best-cf-domains/main/best-cf-domain.txt?port=443",
    "cmliu":            "https://raw.githubusercontent.com/cmliu/WorkerVless2sub/main/addressesapi.txt?port=443",
    "coolapk":          "https://raw.githubusercontent.com/Coolapk-Code9527/Cloudflare-IP/main/ip.txt?port=443",
    "tiancheng":        "https://bestcf.pages.dev/tiancheng/all.txt?port=443",
    "090227_ct":        "https://addressesapi.090227.xyz/ct?port=443",
    "090227_cfyes":     "https://addressesapi.090227.xyz/CloudFlareYes?port=443",
    "my_source":        "https://raw.githubusercontent.com/LancelotRar/best-cf-ips/main/best-cf-ip-collected.txt",

    # ---- 自由添加，格式随意，自动识别 ----
    # "my_source": "https://example.com/anything.txt",
}

# ---- 按国家分组的源：URL 模板里用 {cc} 占位 ----
GROUPED_SOURCES: Dict[str, str] = {
    "proxifly": "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/countries/{cc}/data.txt?port=443",
    "gslege":   "https://raw.githubusercontent.com/gslege/CloudflareIP/refs/heads/main/{cc}.txt",
}

GROUPED_COUNTRIES = ["HK", "TW", "US", "SG", "JP", "KR", "NL", "DE"]

# 允许的代理端口
ALLOWED_PORTS = {
    "443", "8443", "2053", "2083", "2087", "2096",
    "80", "8080", "3128", "1080", "8888", "8880",
    "2052", "2082", "2086", "2095", "10808", "10809",
}

# 输出顺序
ORDER = ["HK", "SG", "JP", "KR", "TW", "US", "DE", "NL", "AE", "CF"]
OUTPUT_FILE = "best_ips_grouped_full.txt"
DEFAULT_PORT = "443"


# ============================================================
# 工具
# ============================================================
def log(msg: str) -> None:
    print(msg)


def fetch(url: str, timeout: int = 20) -> str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="ignore")
    except Exception as e:
        log(f"[获取失败] {url}: {e}")
        return ""


IPV4_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


def is_ipv4(s: str) -> bool:
    if not IPV4_RE.match(s):
        return False
    return all(0 <= int(p) <= 255 for p in s.split("."))


def valid_host(host: str) -> bool:
    """IP 做范围校验，域名只做基本字符检查"""
    if IPV4_RE.match(host):
        return is_ipv4(host)
    return bool(re.match(r"^[A-Za-z0-9\.\-]+$", host)) and "." in host


# ============================================================
# 收集器
# ============================================================
class Collector:
    def __init__(self) -> None:
        self.results: Dict[str, List[str]] = defaultdict(list)
        self._seen: set = set()

    def add(self, host_port: str, cc: str, region: str = "") -> None:
        if ":" not in host_port:
            return
        host, _, port = host_port.rpartition(":")
        if not host or not port.isdigit():
            return
        if not valid_host(host):
            return
        key = f"{cc}-{region}" if region else cc
        line = f"{host}:{port}#{key}"
        if line in self._seen:
            return
        self._seen.add(line)
        self.results[cc].append(line)


# ============================================================
# 自动解析：按优先级尝试各种正则
# ============================================================
PATTERNS: List[tuple] = [
    # 1. 带协议的代理：socks5://1.2.3.4:1080 / http://...
    ("proxy",  re.compile(r"(?:socks5|https?|http)://([\d\.]+):(\d+)")),

    # 2. host:port#CC  (IP 或域名，大写两字母国家码)
    ("hp_cc",  re.compile(r"^([\w\.\-]+):(\d+)#([A-Z]{2})\b")),

    # 3. host:port#region (IP/域名，任意地区标识)
    ("hp_tag", re.compile(r"^([\w\.\-]+):(\d+)#([\w\-]+)")),

    # 4. host:port (无 #)
    ("hp",     re.compile(r"^([\w\.\-]+):(\d+)\s*$")),

    # 5. ip#CC
    ("ip_cc",  re.compile(r"^([\d\.]+)#([A-Z]{2})\b")),

    # 6. ip#region
    ("ip_tag", re.compile(r"^([\d\.]+)#([\w\-]+)")),

    # 7. 纯 IP
    ("ip",     re.compile(r"^([\d\.]+)\s*$")),
]


def auto_parse_line(line: str):
    """
    返回 (host, port, cc, region) 或 None
    cc 用于分组；region 为可选子标签
    当 cc 无法识别时返回 "CF"，由调用方决定是否用外层国家码覆盖
    """
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("//"):
        return None

    for kind, pat in PATTERNS:
        m = pat.search(line) if kind == "proxy" else pat.match(line)
        if not m:
            continue

        if kind == "proxy":
            ip, port = m.group(1), m.group(2)
            if port in ALLOWED_PORTS and is_ipv4(ip):
                return (ip, port, "CF", "FreeProxy")

        elif kind == "hp_cc":
            host, port, cc = m.group(1), m.group(2), m.group(3)
            if valid_host(host):
                return (host, port, cc, "")

        elif kind == "hp_tag":
            host, port, tag = m.group(1), m.group(2), m.group(3)
            if valid_host(host):
                return (host, port, "CF", tag)

        elif kind == "hp":
            host, port = m.group(1), m.group(2)
            if valid_host(host):
                return (host, port, "CF", "")

        elif kind == "ip_cc":
            ip, cc = m.group(1), m.group(2)
            if is_ipv4(ip):
                return (ip, DEFAULT_PORT, cc, "")

        elif kind == "ip_tag":
            ip, tag = m.group(1), m.group(2)
            if is_ipv4(ip):
                return (ip, DEFAULT_PORT, "CF", tag)

        elif kind == "ip":
            ip = m.group(1)
            if is_ipv4(ip):
                return (ip, DEFAULT_PORT, "CF", "Unknown")

    return None


def feed_text(text: str, collector: Collector, default_cc: str = "", region: str = "") -> int:
    """
    解析整段文本并写入 collector。
    default_cc: 当解析结果没有明确国家码时使用（分组源的外层国家码）
    region:     统一追加的子标签（如 FreeProxy / Gslege）
    返回成功条数。
    """
    count = 0
    for raw in text.splitlines():
        parsed = auto_parse_line(raw)
        if not parsed:
            continue
        host, port, cc, tag = parsed

        # 若解析出的 cc 是默认的 CF（表示没有明确国家），且提供了 default_cc，则用外层国家
        if default_cc and cc == "CF":
            cc = default_cc

        # region 优先使用调用方传入的（比如 FreeProxy），否则用解析出的 tag
        final_region = region or tag
        collector.add(f"{host}:{port}", cc, final_region)
        count += 1
    return count


# ============================================================
# 主流程
# ============================================================
def main() -> None:
    collector = Collector()
    stats: Dict[str, int] = defaultdict(int)

    # 1. 普通源
    for name, url in SOURCES.items():
        log(f"[抓取] {name}")
        text = fetch(url)
        if not text:
            continue
        n = feed_text(text, collector)
        stats[name] = n

    # 2. 分组源（按国家循环）
    for src_name, tmpl in GROUPED_SOURCES.items():
        for cc in GROUPED_COUNTRIES:
            url = tmpl.format(cc=cc)
            log(f"[抓取] {src_name}/{cc}")
            text = fetch(url)
            if not text:
                continue
            n = feed_text(text, collector, default_cc=cc, region=src_name)
            stats[f"{src_name}/{cc}"] += n

    # 3. 输出
    lines: List[str] = []
    seen_out: set = set()

    def emit(cc: str) -> None:
        for item in sorted(set(collector.results.get(cc, []))):
            if item not in seen_out:
                seen_out.add(item)
                lines.append(item)

    for cc in ORDER:
        emit(cc)
    for cc in sorted(collector.results.keys()):
        if cc not in ORDER:
            emit(cc)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))

    # 4. 统计
    total_src = sum(stats.values())
    log("---- 各源命中统计 ----")
    for name, n in stats.items():
        if n > 0:
            log(f"  {name}: {n} 条")
    log(f"原始命中合计: {total_src}")
    log(f"去重后输出: {len(lines)} 条 -> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
