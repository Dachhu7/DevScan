#!/usr/bin/env python3
from __future__ import annotations
import asyncio, logging, re
from typing import Dict, Set
from urllib.parse import urljoin, urlparse, urldefrag
import aiohttp, requests
from bs4 import BeautifulSoup

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except:
    PLAYWRIGHT_AVAILABLE = False

CONCURRENCY = 6
REQUEST_TIMEOUT = 20
MAX_PAGES = 1000
FOLLOW_SUBDOMAINS = False
USER_AGENT = "DevScan/1.0 (+https://example.com/)"

COMMON_SENSITIVE_PATHS = [
    ".git/HEAD", ".git/config", ".env", "backup.zip", "db_dump.sql",
    "config.php.bak", "wp-config.php.bak", "id_rsa", ".htpasswd"
]

COMMON_ADMIN_PATHS = ["admin","administrator","wp-admin","login","cpanel","dashboard"]

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("DevScan")

JS_URL_RE = re.compile(r"""(?:"|')(?P<full_url>https?://[^"']+)(?:"|')|fetch\(["'](?P<fetch_url>/[^"']+)["']\)""")
HTTP_LINK_RE = re.compile(r"https?://[^\s'\"<>]+")

visited_urls_global: Set[str] = set()
vuln_report: Dict[str, Set[str]] = dict()

def normalize_url(url: str, base: str) -> str:
    if not url: return ""
    url = url.strip()
    url, _ = urldefrag(url)
    if url.startswith("//"): url = urlparse(base).scheme + ":" + url
    elif url.startswith("/"): url = urljoin(base,url)
    elif not re.match(r"https?://", url): url = urljoin(base,url)
    return url

def same_site(url:str, base_domain:str, follow_subdomains:bool)->bool:
    try:
        p = urlparse(url)
        return p.netloc.endswith(base_domain) if follow_subdomains else p.netloc==base_domain
    except: return False

def detect_vulnerability(url:str, status:int, headers:Dict[str,str], content:str)->Set[str]:
    issues = set()
    if status==200: issues.add("Publicly Accessible")
    if status==401: issues.add("Requires Auth (401)")
    if status==403: issues.add("Forbidden (403)")
    security_headers = ["Content-Security-Policy","X-Frame-Options","Strict-Transport-Security","X-XSS-Protection","X-Content-Type-Options"]
    for h in security_headers:
        if h not in headers and h.lower() not in (k.lower() for k in headers): issues.add(f"Missing {h} header")
    text=content.lower()
    if "index of /" in text or "directory listing" in text or "<title>index of" in text: issues.add("Directory listing enabled")
    if any(s in url.lower() for s in COMMON_SENSITIVE_PATHS): issues.add("Sensitive file accessible")
    if any(p in url.lower() for p in COMMON_ADMIN_PATHS): issues.add("Admin panel path detected")
    server=headers.get("Server") or headers.get("server")
    if server: issues.add(f"Server banner: {server}")
    return issues

def extract_links_from_html(text:str, base_url:str)->Set[str]:
    soup=BeautifulSoup(text,"lxml")
    urls=set()
    for tag, attr in [("a","href"),("link","href"),("script","src"),("img","src"),("iframe","src")]:
        for t in soup.find_all(tag):
            u=t.get(attr)
            if u: urls.add(normalize_url(u,base_url))
    for st in soup.find_all("script"):
        if st.string:
            for m in JS_URL_RE.findall(st.string):
                candidate=[x for x in m if x]
                if candidate: urls.add(normalize_url(candidate[0],base_url))
            for m in HTTP_LINK_RE.findall(st.string): urls.add(normalize_url(m,base_url))
    return urls

def fetch_robots_sitemap(base_url:str)->Set[str]:
    discovered=set()
    for path in ["/robots.txt","/sitemap.xml"]:
        try:
            r=requests.get(urljoin(base_url,path),headers={"User-Agent":USER_AGENT},timeout=10)
            if r.status_code==200: discovered.add(urljoin(base_url,path))
        except: pass
    return discovered

async def process_response(url:str,status:int,headers:Dict[str,str],content:str,queue:asyncio.Queue,base_domain:str):
    issues=detect_vulnerability(url,status,headers,content)
    if issues: vuln_report[url]=issues
    if "text/html" in headers.get("Content-Type","") or url.endswith((".html",".htm","/")):
        for link in extract_links_from_html(content,url):
            if same_site(link,base_domain,FOLLOW_SUBDOMAINS) and link not in visited_urls_global:
                await queue.put(link)

async def worker(session:aiohttp.ClientSession,queue:asyncio.Queue,base_domain:str,use_playwright:bool):
    while True:
        url=await queue.get()
        if url is None: queue.task_done(); break
        if url in visited_urls_global: queue.task_done(); continue
        if len(visited_urls_global)>=MAX_PAGES: queue.task_done(); continue
        visited_urls_global.add(url)
        try:
            headers={"User-Agent":USER_AGENT}
            async with session.get(url,headers=headers,timeout=REQUEST_TIMEOUT) as resp:
                content=await resp.text()
                await process_response(url,resp.status,dict(resp.headers),content,queue,base_domain)
        except Exception as e: logger.debug(f"[Error] {url}: {e}")
        finally: queue.task_done()

async def crawl(start_url:str,use_playwright:bool=False):
    base_domain=urlparse(start_url).netloc
    queue=asyncio.Queue()
    await queue.put(start_url)
    for u in fetch_robots_sitemap(start_url): await queue.put(u)
    async with aiohttp.ClientSession() as session:
        tasks=[asyncio.create_task(worker(session,queue,base_domain,use_playwright)) for _ in range(CONCURRENCY)]
        await queue.join()
        for t in tasks: await queue.put(None)
        await asyncio.gather(*tasks,return_exceptions=True)
    return {k:list(v) for k,v in vuln_report.items()}

def run_scan(start_url:str):
    visited_urls_global.clear()
    vuln_report.clear()
    report=asyncio.run(crawl(start_url))
    logger.info(f"\nScan complete! Found {len(report)} URLs with potential issues.\n")
    return report
