#!/usr/bin/env python3
"""
  ██████╗██████╗  █████╗ ██████╗ ██████╗  █████╗ ██╗    ██╗██╗     ███████╗██████╗
 ██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝██╔══██╗
 ██║     ██████╔╝███████║██████╔╝██████╔╝███████║██║ █╗ ██║██║     █████╗  ██████╔╝
 ██║     ██╔══██╗██╔══██║██╔══██╗██╔══██╗██╔══██║██║███╗██║██║     ██╔══╝  ██╔══██╗
 ╚██████╗██║  ██║██║  ██║██████╔╝██║  ██║██║  ██║╚███╔███╔╝███████╗███████╗██║  ██║
  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝

  [ __      __
   (  \____/  )      C R A B R A W L E R 
    \__ oo __/     -------------------------
     /      \      [ Status: Ready to pinch ]
 ]

  CrabRawler v1.0  ·  Web Reconnaissance Spider
  Uso: python crabrawler.py
"""

import json
import sys
import re
import scrapy
from scrapy.http import Request
from scrapy.crawler import CrawlerProcess
from urllib.parse import urljoin, urldefrag, urlparse

# ─── CONSTANTES ───────────────────────────────────────────────────────────────
INTERESTING = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".rar",
               ".bak", ".sql", ".env", ".conf", ".config")

NIVELES = {
    1: dict(DOWNLOAD_DELAY=5,   RANDOMIZE_DOWNLOAD_DELAY=True,
            AUTOTHROTTLE_ENABLED=True,  AUTOTHROTTLE_MAX_DELAY=60,
            label="[1] Sigilo total    · delay 5s   · recomendado con IDS/WAF"),
    2: dict(DOWNLOAD_DELAY=3,   RANDOMIZE_DOWNLOAD_DELAY=True,
            AUTOTHROTTLE_ENABLED=True,  AUTOTHROTTLE_MAX_DELAY=30,
            label="[2] Cauteloso       · delay 3s"),
    3: dict(DOWNLOAD_DELAY=1,   RANDOMIZE_DOWNLOAD_DELAY=True,
            AUTOTHROTTLE_ENABLED=True,  AUTOTHROTTLE_MAX_DELAY=10,
            label="[3] Normal          · delay 1s"),
    4: dict(DOWNLOAD_DELAY=0.5, RANDOMIZE_DOWNLOAD_DELAY=True,
            AUTOTHROTTLE_ENABLED=True,  AUTOTHROTTLE_MAX_DELAY=5,
            label="[4] Agresivo        · delay 0.5s"),
    5: dict(DOWNLOAD_DELAY=0,   RANDOMIZE_DOWNLOAD_DELAY=False,
            AUTOTHROTTLE_ENABLED=False, AUTOTHROTTLE_MAX_DELAY=0,
            label="[5] Sin límite      · sin delay"),
}

# ─── HELPERS ──────────────────────────────────────────────────────────────────
def sep(msg):
    line = "═" * 62
    return {"fase": "---",
            "url": f"\n{line}\n  {msg}\n{line}",
            "status": None, "titulo": None, "contenido": None}


def menu():
    print(__doc__)

    target = input("  [?] URL objetivo (ej: https://ejemplo.com/ruta): ").strip()
    if not target:
        print("  [!] URL requerida. Saliendo.")
        sys.exit(1)
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    target = target.rstrip("/")

    print("\n  Nivel de agresividad:")
    for cfg in NIVELES.values():
        print(f"      {cfg['label']}")

    while True:
        try:
            nivel = int(input("\n  [?] Nivel (1-5): ").strip())
            if 1 <= nivel <= 5:
                break
            print("  [!] Introduce un número entre 1 y 5.")
        except ValueError:
            print("  [!] Número inválido.")

    output = input("  [?] Archivo de salida [results.json]: ").strip() or "results.json"
    print()
    return target, nivel, output


# ═══════════════════════════════════════════════════════════════════════════════
# SPIDER
# ═══════════════════════════════════════════════════════════════════════════════
class CrabRawler(scrapy.Spider):
    name = "crabrawler"

    # Ajustes fijos — los de agresividad llegan desde CrawlerProcess
    custom_settings = {
        "CONCURRENT_REQUESTS": 1,       # orden garantizado entre fases
        "HTTPERROR_ALLOW_ALL":  True,    # no descartar nada por código HTTP
        "ROBOTSTXT_OBEY":       False,   # en pentest ético revisamos robots.txt a mano
        "USER_AGENT":           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    }

    # ── Init ──────────────────────────────────────────────────────────────────
    def __init__(self, target, output_file="results.json", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._target        = target.rstrip("/")
        self._real_base     = None
        self._sitemap_url   = f"{self._target}/sitemap.xml"
        self._fix           = lambda u: u   # reemplaza dominios placeholder
        self._seen          = set()
        self._fase2_pending = 0             # contador visitas pendientes en fase 2
        self._fase2_buffer  = []            # acumula URLs de sub-sitemaps
        self._items         = []            # almacén nativo para json.dump
        self._output_file   = output_file

    # ── Cierre: escribe JSON ───────────────────────────────────────────────────
    def closed(self, reason):
        with open(self._output_file, "w", encoding="utf-8") as fh:
            json.dump(self._items, fh, ensure_ascii=False, indent=2)
        print(f"  [+] {len(self._items)} registros → {self._output_file}")
        print(f"  [+] Spider cerrado: {reason}")

    # ── Helper: registra y devuelve el item ───────────────────────────────────
    def _rec(self, item):
        self._items.append(item)
        return item

    # =========================================================================
    # ARRANQUE — start_requests (estilo Gemini/file2)
    # Nota: Scrapy 2.13+ usa start() internamente; el shim de abajo lo adapta.
    # =========================================================================
    def start_requests(self):
        yield Request(self._target, callback=self._detect_domain)

    # Shim para Scrapy 2.13+ (que llama a start() en lugar de start_requests())
    async def start(self):
        for req in self.start_requests():
            yield req

    # ── Detecta dominio real tras posibles redirects ───────────────────────────
    def _detect_domain(self, response):
        self._real_base   = response.url.rstrip("/")
        root              = (f"{urlparse(self._real_base).scheme}://"
                             f"{urlparse(self._real_base).netloc}")
        self._sitemap_url = f"{self._real_base}/sitemap.xml"
        self.logger.info(f"Dominio real detectado: {self._real_base}")
        yield Request(f"{root}/robots.txt",
                      callback=self._parse_robots,
                      errback=self._skip_robots,
                      dont_filter=True)

    # =========================================================================
    # ROBOTS.TXT
    # =========================================================================
    def _parse_robots(self, response):
        yield self._rec(sep("ROBOTS.TXT"))
        yield self._rec({"fase": "robots", "url": response.url,
                         "status": response.status, "titulo": "robots.txt",
                         "contenido": response.text})

        for path in re.findall(r"(?i)^Disallow:\s*(.+)", response.text, re.M):
            path = path.strip()
            if path and path != "/":
                full = urljoin(self._real_base + "/", path.lstrip("/"))
                yield self._rec({"fase": "robots_disallow", "url": full,
                                 "status": None,
                                 "titulo": "Disallow en robots.txt",
                                 "contenido": None})

        hints = re.findall(r"(?i)^Sitemap:\s*(.+)", response.text, re.M)
        if hints:
            self._sitemap_url = hints[0].strip()
            self.logger.info(f"[robots.txt] Sitemap alternativo: {self._sitemap_url}")

        yield from self._lanzar_fase1()

    def _skip_robots(self, _):
        self.logger.info("[robots.txt] No disponible, continuando sin él")
        yield from self._lanzar_fase1()

    # =========================================================================
    # FASE 1 — SITEMAP RAW
    # =========================================================================
    def _lanzar_fase1(self):
        yield self._rec(sep("FASE 1 — SITEMAP RAW"))
        yield Request(self._sitemap_url,
                      callback=self._fase1_raw,
                      errback=self._fase1_error,
                      dont_filter=True)

    def _fase1_raw(self, response):
        self.logger.info(f"[FASE 1] HTTP {response.status} — {response.url}")
        yield self._rec({"fase": 1, "url": response.url,
                         "status": response.status,
                         "titulo": "SITEMAP RAW",
                         "contenido": response.text})

        es_xml = ("<urlset" in response.text or "<sitemapindex" in response.text)
        if response.status == 200 and es_xml:
            yield self._rec(sep("FASE 2 — SITEMAP PARSEADO"))
            yield Request(response.url, callback=self._fase2_parse,
                          dont_filter=True)
        else:
            yield self._rec({"fase": 2, "url": "—", "status": None,
                             "titulo": "FASE 2 OMITIDA — sin sitemap válido",
                             "contenido": None})
            yield from self._lanzar_fase3()

    def _fase1_error(self, failure):
        self.logger.info(f"[FASE 1] Error de red: {failure.value}")
        yield self._rec({"fase": 1, "url": self._sitemap_url, "status": "ERROR",
                         "titulo": "SITEMAP NO ACCESIBLE",
                         "contenido": str(failure.value)})
        yield self._rec({"fase": 2, "url": "—", "status": None,
                         "titulo": "FASE 2 OMITIDA — sitemap no accesible",
                         "contenido": None})
        yield from self._lanzar_fase3()

    # =========================================================================
    # FASE 2 — SITEMAP PARSEADO
    # Recursión limpia (estilo Gemini/file2).
    # Contador _fase2_pending garantiza que el separador aparece
    # DESPUÉS del último item de fase 2 (del file1).
    # =========================================================================
    def _fase2_parse(self, response):
        response.selector.remove_namespaces()

        sample = (response.xpath("//url/loc/text()").getall() or
                  response.xpath("//sitemap/loc/text()").getall())
        if sample:
            self._fix = self._build_fixer(sample[0].strip())

        # ── Sitemap index ────────────────────────────────────────────────────
        sub = response.xpath("//sitemap/loc/text()").getall()
        if sub:
            self.logger.info(f"[FASE 2] Index detectado — {len(sub)} sub-sitemaps")
            self._fase2_pending = len(sub)
            self._fase2_buffer  = []
            for raw in sub:
                yield Request(self._fix(raw.strip()),
                              callback=self._fase2_sub_collect,
                              dont_filter=True)
            return

        # ── Sitemap normal ───────────────────────────────────────────────────
        urls = [self._fix(u.strip())
                for u in response.xpath("//url/loc/text()").getall()]
        self.logger.info(f"[FASE 2] {len(urls)} URLs encontradas")
        yield from self._lanzar_visitas_fase2(urls)

    def _fase2_sub_collect(self, response):
        """
        Recolecta URLs de cada sub-sitemap en el buffer.
        Solo lanza las visitas cuando TODOS los sub-sitemaps han respondido
        (control de estado del file1).
        """
        response.selector.remove_namespaces()
        urls = [self._fix(u.strip())
                for u in response.xpath("//url/loc/text()").getall()]
        self._fase2_buffer.extend(urls)

        self._fase2_pending -= 1
        if self._fase2_pending == 0:
            self.logger.info(
                f"[FASE 2] Todos los sub-sitemaps procesados "
                f"— {len(self._fase2_buffer)} URLs totales"
            )
            yield from self._lanzar_visitas_fase2(self._fase2_buffer)

    def _lanzar_visitas_fase2(self, urls):
        if not urls:
            yield from self._lanzar_fase3()
            return
        self._fase2_pending = len(urls)
        for url in urls:
            self._seen.add(url.rstrip("/"))
            yield Request(url, callback=self._fase2_visit, dont_filter=True)

    def _fase2_visit(self, response):
        """
        Emite el item y decrementa el contador.
        El separador fase2→fase3 se emite desde aquí, cuando el contador
        llega a 0, garantizando que aparece DESPUÉS del último item.
        """
        yield self._rec({"fase": 2, "url": response.url,
                         "status": response.status,
                         "titulo": response.css("title::text").get("").strip(),
                         "contenido": response.text[:3000]})

        self._fase2_pending -= 1
        if self._fase2_pending == 0:
            yield from self._lanzar_fase3()

    # =========================================================================
    # FASE 3 — FUERZA BRUTA POR ENLACES HTML
    # =========================================================================
    def _lanzar_fase3(self):
        yield self._rec(sep("FASE 3 — FUERZA BRUTA HTML"))
        yield Request(self._real_base, callback=self._fase3_crawl,
                      dont_filter=True)

    def _fase3_crawl(self, response):
        key = response.url.rstrip("/")
        if key not in self._seen:
            self._seen.add(key)
            yield self._rec({"fase": 3, "url": response.url,
                             "status": response.status,
                             "titulo": response.css("title::text").get("").strip(),
                             "contenido": response.text[:3000]})

        for href in response.css("a::attr(href)").getall():
            if not href or href.startswith(("#", "mailto:", "javascript:", "tel:")):
                continue
            link, _ = urldefrag(urljoin(response.url, href))
            if not link.lower().startswith(("http://", "https://")):
                continue
            if not link.startswith(self._real_base):
                continue
            key = link.rstrip("/")
            if key in self._seen:
                continue
            self._seen.add(key)
            if link.lower().endswith(INTERESTING):
                yield self._rec({"fase": 3, "url": link, "status": None,
                                 "titulo": None, "contenido": None})
            else:
                yield response.follow(link, callback=self._fase3_crawl)

    # =========================================================================
    # HELPER — reemplaza dominio placeholder por el dominio real
    # =========================================================================
    def _build_fixer(self, sample_loc: str):
        ps = urlparse(sample_loc)
        pr = urlparse(self._real_base)
        if ps.netloc == pr.netloc:
            self.logger.info("[FASE 2] URLs del sitemap usan el dominio correcto")
            return lambda u: u
        placeholder = f"{ps.scheme}://{ps.netloc}"
        real_prefix = f"{pr.scheme}://{pr.netloc}{pr.path.rstrip('/')}"
        self.logger.info(f"[FASE 2] Placeholder: {placeholder} → {real_prefix}")
        return lambda u: u.replace(placeholder, real_prefix, 1)


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    target, nivel, output = menu()
    agr = NIVELES[nivel]

    print(f"  [*] Objetivo    : {target}")
    print(f"  [*] Agresividad : {agr['label'].strip()}")
    print(f"  [*] Salida      : {output}")
    print()

    process = CrawlerProcess({
        "LOG_LEVEL":               "WARN",
        "DOWNLOAD_DELAY":          agr["DOWNLOAD_DELAY"],
        "RANDOMIZE_DOWNLOAD_DELAY": agr["RANDOMIZE_DOWNLOAD_DELAY"],
        "AUTOTHROTTLE_ENABLED":    agr["AUTOTHROTTLE_ENABLED"],
        "AUTOTHROTTLE_MAX_DELAY":  agr["AUTOTHROTTLE_MAX_DELAY"],
    })
    process.crawl(CrabRawler, target=target, output_file=output)
    process.start()