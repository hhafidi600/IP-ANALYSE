"""
Core networking tool logic. Deliberately dependency-free (stdlib only)
so the app has nothing extra to install or that can go missing on
whatever machine it's deployed to.
"""

import ipaddress
import socket
import subprocess
import platform
import asyncio
import time

COMMON_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 80, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 179, 389, 443, 445, 465, 514, 587, 631, 993, 995, 1080,
    1433, 1521, 1723, 2049, 2082, 2083, 3000, 3306, 3389, 5000, 5432,
    5900, 5985, 6379, 8000, 8080, 8443, 8888, 9000, 9090, 9200, 27017,
]


# ---------------------------------------------------------------- subnet
def subnet_info(cidr):
    interface = ipaddress.ip_interface(cidr)
    network = interface.network
    usable = max(network.num_addresses - 2, 0)
    hosts = list(network.hosts())
    return {
        "ip": str(interface.ip), "netmask": str(network.netmask),
        "network": str(network.network_address), "broadcast": str(network.broadcast_address),
        "total": network.num_addresses, "usable": usable,
        "first_host": str(hosts[0]) if usable else "N/A",
        "last_host": str(hosts[-1]) if usable else "N/A",
    }


# ---------------------------------------------------------------- ip check
def ip_classify(ip_input):
    ip_obj = ipaddress.ip_address(ip_input)
    if ip_obj.is_private:
        category = "Private"
    elif ip_obj.is_loopback:
        category = "Loopback"
    elif ip_obj.is_multicast:
        category = "Multicast"
    elif ip_obj.is_link_local:
        category = "Link-local (APIPA)"
    else:
        category = "Public"

    ranges = [
        {"range": r, "match": ip_obj in ipaddress.ip_network(r)}
        for r in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    ]
    return {"ip": str(ip_obj), "category": category, "ranges": ranges}


# ---------------------------------------------------------------- port scan
async def _scan_one(ip, port, sem, timeout=0.35):
    async with sem:
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "unknown"
            return {"port": port, "service": service}
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None


async def _scan_many(ip, ports, concurrency=500):
    sem = asyncio.Semaphore(concurrency)
    results = await asyncio.gather(*[_scan_one(ip, p, sem) for p in ports])
    return [r for r in results if r]


def port_scan(target, mode="quick", start=1, end=1024):
    target_ip = socket.gethostbyname(target)
    if mode == "quick":
        ports = COMMON_PORTS
    else:
        start, end = int(start), int(end)
        if end - start > 10000:
            end = start + 10000
        ports = list(range(start, end + 1))

    started = time.time()
    open_ports = asyncio.run(_scan_many(target_ip, ports))
    elapsed = round(time.time() - started, 2)
    open_ports.sort(key=lambda x: x["port"])
    return {"target_ip": target_ip, "open_ports": open_ports, "scanned": len(ports), "elapsed": elapsed}


# ---------------------------------------------------------------- ping sweep
def _ping_host(ip):
    is_windows = platform.system().lower() == "windows"
    param = "-n" if is_windows else "-c"
    timeout_param = "-w" if is_windows else "-W"
    timeout_value = "500" if is_windows else "1"
    command = ["ping", param, "1", timeout_param, timeout_value, str(ip)]
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        return result.returncode == 0
    except Exception:
        return False


def ping_sweep(network_input):
    from concurrent.futures import ThreadPoolExecutor, as_completed
    network = ipaddress.ip_network(network_input, strict=False)
    hosts = list(network.hosts())
    if len(hosts) > 512:
        hosts = hosts[:512]

    started = time.time()
    alive = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(_ping_host, ip): ip for ip in hosts}
        for future in as_completed(futures):
            ip = futures[future]
            if future.result():
                alive.append(str(ip))
    elapsed = round(time.time() - started, 2)
    return {"alive": sorted(alive), "scanned": len(hosts), "total": network.num_addresses - 2, "elapsed": elapsed}


# ---------------------------------------------------------------- traceroute
def traceroute(target):
    is_windows = platform.system().lower() == "windows"
    cmd = ["tracert", "-d", "-h", "20", target] if is_windows else ["traceroute", "-n", "-m", "20", target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout or result.stderr
        return {"output": output.strip()}
    except FileNotFoundError:
        raise RuntimeError("traceroute/tracert isn't available on this system")
    except subprocess.TimeoutExpired:
        raise RuntimeError("traceroute timed out")


# ---------------------------------------------------------------- dns lookup
def dns_lookup(domain):
    a_records, aaaa_records = [], []
    try:
        infos = socket.getaddrinfo(domain, None)
    except socket.gaierror as e:
        raise RuntimeError(f"could not resolve {domain}: {e}")

    seen = set()
    for family, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        if ip in seen:
            continue
        seen.add(ip)
        (a_records if family == socket.AF_INET else aaaa_records).append(ip)

    reverse = None
    if a_records:
        try:
            reverse = socket.gethostbyname_ex(domain)[0]
        except Exception:
            reverse = None

    return {"domain": domain, "a_records": a_records, "aaaa_records": aaaa_records, "reverse": reverse}


# ---------------------------------------------------------------- whois
def _whois_query(server, query, timeout=6):
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode(errors="ignore")


def whois_lookup(domain):
    domain = domain.strip().lower()
    tld = domain.rsplit(".", 1)[-1]
    try:
        iana_resp = _whois_query("whois.iana.org", tld)
    except OSError as e:
        raise RuntimeError(f"could not reach whois.iana.org: {e}")

    referral_server = None
    for line in iana_resp.splitlines():
        if line.lower().startswith("whois:"):
            referral_server = line.split(":", 1)[1].strip()
            break

    server_used = referral_server or "whois.iana.org"
    try:
        raw = _whois_query(server_used, domain)
    except OSError as e:
        raise RuntimeError(f"could not reach {server_used}: {e}")

    return {"server": server_used, "raw": raw[:5000].strip()}