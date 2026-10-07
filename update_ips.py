import re
import os
from collections import defaultdict
from datetime import datetime, timezone, timedelta
import urllib.request

SOURCES = {
    "gaoji": "https://ips.gaoji.uk/best_ips.txt?port=443",
    "lancelot_ips": "https://raw.githubusercontent.com/LancelotRar/best-cf-ips/main/best-cf-ip-collected.txt?port=443",
    "lancelot_domains": "https://raw.githubusercontent.com/LancelotRar/best-cf-domains/main/best-cf-domain.txt?port=443",
    "cmliu": "https://raw.githubusercontent.com/cmliu/WorkerVless2sub/main/addressesapi.txt?port=443",
    "coolapk": "https://raw.githubusercontent.com/Coolapk-Code9527/Cloudflare-IP/main/ip.txt?port=443",
    "tiancheng": "https://bestcf.pages.dev/tiancheng/all.txt?port=443",
    "090227_ct": "https://addressesapi.090227.xyz/ct?port=443",
    "090227_cfyes": "https://addressesapi.090227.xyz/CloudFlareYes?port=443",
}

PROXIFLY = {
    "HK": "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/countries/HK/data.txt?port=443",
    "US": "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/countries/US/data.txt?port=443",
    "SG": "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/countries/SG/data.txt?port=443",
    "JP": "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/countries/JP/data.txt?port=443",
    "KR": "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/countries/KR/data.txt?port=443",
    "NL": "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/countries/NL/data.txt?port=443",
    "DE": "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/countries/DE/data.txt?port=443",
}

def fetch(url: str) -> str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"获取失败 {url}: {e}")
        return ""

def main():
    results = defaultdict(list)

    def add(ip_port, cc, region=""):
        if not ip_port or not re.match(r'^[\w\.\-]+:\d+$', ip_port):
            return
        ip = ip_port.split(":")[0]
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
            parts = list(map(int, ip.split(".")))
            if any(p > 255 for p in parts):
                return
        key = f"{cc}-{region}" if region else cc
        line = f"{ip_port}#{key}"
        if line not in results[cc]:
            results[cc].append(line)

    # 优质源
    data = {k: fetch(v) for k, v in SOURCES.items()}

    for line in data["gaoji"].splitlines():
        m = re.match(r'([\d\.]+:\d+)#([A-Z]{2})', line.strip())
        if m: add(m.group(1), m.group(2))

    for line in data["lancelot_ips"].splitlines():
        if line.startswith("#"): continue
        m = re.match(r'([\d\.]+:\d+)#([A-Z]{2})', line.strip())
        if m: add(m.group(1), m.group(2))

    for line in data["lancelot_domains"].splitlines():
        m = re.match(r'([^:\s]+):(\d+)#', line.strip())
        if m: add(f"{m.group(1)}:{m.group(2)}", "CF", "Domain")

    for line in data["cmliu"].splitlines():
        m = re.match(r'([\d\.]+:\d+)#([A-Z]{2})', line.strip())
        if m: add(m.group(1), m.group(2))

    for line in data["coolapk"].splitlines():
        line = line.strip()
        if re.match(r'^[\d\.]+$', line):
            parts = line.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                add(f"{line}:443", "CF", "Unknown")

    for line in data["tiancheng"].splitlines():
        m = re.search(r'([\d\.]+:\d+)#.*?([A-Z]{2})', line.strip())
        if m: add(m.group(1), m.group(2))

    for line in data["090227_ct"].splitlines():
        m = re.match(r'([\d\.]+)#', line.strip())
        if m: add(f"{m.group(1)}:443", "CF", "CT")

    for line in data["090227_cfyes"].splitlines():
        m = re.match(r'([\d\.]+)#(\w+)?', line.strip())
        if m:
            region = m.group(2) or ""
            add(f"{m.group(1)}:443", "CF", region)

    # proxifly 免费代理
    for cc, url in PROXIFLY.items():
        content = fetch(url)
        for line in content.splitlines():
            m = re.search(r'(?:socks5|https?|http)://([\d\.]+):(\d+)', line.strip())
            if m:
                ip, port = m.group(1), m.group(2)
                if port in ["443","8443","2053","2083","2087","2096","80","8080","3128","1080","8888","8880","2052","2082","2086","2095","10808","10809"]:
                    add(f"{ip}:{port}", cc, "FreeProxy")

    # 输出
    tz = timezone(timedelta(hours=8))
    now = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")

    # lines = []
    # lines.append("# 按国家分组的完整 IP / 域名列表（包含 proxifly 免费代理）")
    # lines.append("# 格式: ip:端口#国家代码-地区")
    # lines.append(f"# 生成时间: {now} (UTC+8)")
    # lines.append("# 注意: 带 FreeProxy 的节点质量参差不齐，建议优先使用无此标注的节点")
    # lines.append("")

    order = ["HK", "SG", "JP", "KR", "TW", "US", "DE", "NL", "AE", "CF"]
    total = 0
    for cc in order:
        items = sorted(set(results.get(cc, [])))
        if not items: continue
        free = sum(1 for x in items if "FreeProxy" in x)
        premium = len(items) - free
        lines.append(f"# 【{cc}】 共 {len(items)} 条 (优质:{premium} / 免费代理:{free})")
        lines.extend(items)
        lines.append("")
        total += len(items)

    for cc in sorted(results.keys()):
        if cc not in order:
            items = sorted(set(results[cc]))
            lines.append(f"# 【{cc}】 共 {len(items)} 条")
            lines.extend(items)
            lines.append("")
            total += len(items)

    lines.append(f"# 总计: {total} 条")

    with open("best_ips_grouped_full.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"更新完成，共 {total} 条")

if __name__ == "__main__":
    main()
