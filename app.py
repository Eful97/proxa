import asyncio
import logging
import re
import sys
import random
import os
import urllib.parse
from urllib.parse import urlparse, urljoin
import xml.etree.ElementTree as ET
import aiohttp
from aiohttp import web
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from aiohttp_proxy import ProxyConnector
from dotenv import load_dotenv

load_dotenv() # Carica le variabili dal file .env

# Configurazione logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s:%(name)s:%(message)s'
)

logger = logging.getLogger(__name__)

# --- Configurazione Proxy ---
def parse_proxies(proxy_env_var: str) -> list:
    """Analizza una stringa di proxy separati da virgola da una variabile d'ambiente."""
    proxies_str = os.environ.get(proxy_env_var, "").strip()
    if proxies_str:
        return [p.strip() for p in proxies_str.split(',') if p.strip()]
    return []

GLOBAL_PROXIES = parse_proxies('GLOBAL_PROXY')
VAVOO_PROXIES = parse_proxies('VAVOO_PROXY')
DLHD_PROXIES = parse_proxies('DLHD_PROXY')

if GLOBAL_PROXIES: logging.info(f"🌍 Caricati {len(GLOBAL_PROXIES)} proxy globali.")
if VAVOO_PROXIES: logging.info(f"🎬 Caricati {len(VAVOO_PROXIES)} proxy Vavoo.")
if DLHD_PROXIES: logging.info(f"📺 Caricati {len(DLHD_PROXIES)} proxy DLHD.")

# Aggiungi path corrente per import moduli
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# --- Moduli Esterni ---
VavooExtractor, DLHDExtractor, VixSrcExtractor, PlaylistBuilder, SportsonlineExtractor = None, None, None, None, None

try:
    from vavoo_extractor import VavooExtractor
    logger.info("✅ Modulo VavooExtractor caricato.")
except ImportError:
    logger.warning("⚠️ Modulo VavooExtractor non trovato. Funzionalità Vavoo disabilitata.")

try:
    from dlhd_extractor import DLHDExtractor
    logger.info("✅ Modulo DLHDExtractor caricato.")
except ImportError:
    logger.warning("⚠️ Modulo DLHDExtractor non trovato. Funzionalità DLHD disabilitata.")

try:
    from playlist_builder import PlaylistBuilder
    logger.info("✅ Modulo PlaylistBuilder caricato.")
except ImportError:
    logger.warning("⚠️ Modulo PlaylistBuilder non trovato. Funzionalità PlaylistBuilder disabilitata.")
    
try:
    from vixsrc_extractor import VixSrcExtractor
    logger.info("✅ Modulo VixSrcExtractor caricato.")
except ImportError:
    logger.warning("⚠️ Modulo VixSrcExtractor non trovato. Funzionalità VixSrc disabilitata.")

try:
    from sportsonline_extractor import SportsonlineExtractor
    logger.info("✅ Modulo SportsonlineExtractor caricato.")
except ImportError:
    logger.warning("⚠️ Modulo SportsonlineExtractor non trovato. Funzionalità Sportsonline disabilitata.")

# --- Classi Unite ---
class ExtractorError(Exception):
    pass

class GenericHLSExtractor:
    def __init__(self, request_headers, proxies=None):
        self.request_headers = request_headers
        self.base_headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        self.session = None
        self.proxies = proxies or []

    def _get_random_proxy(self):
        return random.choice(self.proxies) if self.proxies else None

    async def _get_session(self):
        if self.session is None or self.session.closed:
            proxy = self._get_random_proxy()
            if proxy:
                connector = ProxyConnector.from_url(proxy)
            else:
                connector = TCPConnector(
                    limit=20, limit_per_host=10, 
                    keepalive_timeout=60, enable_cleanup_closed=True, 
                    force_close=False, use_dns_cache=True
                )

            timeout = ClientTimeout(total=60, connect=30, sock_read=30)
            self.session = ClientSession(
                timeout=timeout, connector=connector, 
                headers={'user-agent': self.base_headers['user-agent']}
            )
        return self.session

    async def extract(self, url, **kwargs):
        if not any(pattern in url.lower() for pattern in ['.m3u8', '.mpd', '.ts', 'vixsrc.to/playlist', 'newkso.ru']):
            raise ExtractorError("URL non supportato")

        parsed_url = urlparse(url)
        origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
        headers = self.base_headers.copy()
        headers.update({"referer": origin, "origin": origin})

        for h, v in self.request_headers.items():
            if h.lower() in ["authorization", "x-api-key", "x-auth-token"]:
                headers[h] = v

        return {
            "destination_url": url, 
            "request_headers": headers, 
            "mediaflow_endpoint": "hls_proxy"
        }

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()

class HLSProxy:
    def __init__(self):
        self.extractors = {}
        if PlaylistBuilder:
            self.playlist_builder = PlaylistBuilder()
        else:
            self.playlist_builder = None
    
    async def get_extractor(self, url: str, request_headers: dict):
        try:
            if "vavoo.to" in url:
                key = "vavoo"
                proxies = VAVOO_PROXIES or GLOBAL_PROXIES
                if key not in self.extractors:
                    self.extractors[key] = VavooExtractor(request_headers, proxies=proxies)
                return self.extractors[key]
            elif any(domain in url for domain in ["daddylive", "dlhd"]) or re.search(r'stream-\d+\.php', url):
                key = "dlhd"
                proxies = DLHD_PROXIES or GLOBAL_PROXIES
                if key not in self.extractors:
                    self.extractors[key] = DLHDExtractor(request_headers, proxies=proxies)
                return self.extractors[key]
            elif any(ext in url.lower() for ext in ['.m3u8', '.mpd', '.ts', 'newkso.ru']) or 'vixsrc.to/playlist' in url.lower():
                key = "hls_generic"
                if key not in self.extractors:
                    self.extractors[key] = GenericHLSExtractor(request_headers, proxies=GLOBAL_PROXIES)
                return self.extractors[key]
            elif 'vixsrc.to/' in url.lower() and any(x in url for x in ['/movie/', '/tv/', '/iframe/']):
                key = "vixsrc"
                if key not in self.extractors:
                    self.extractors[key] = VixSrcExtractor(request_headers, proxies=GLOBAL_PROXIES)
                return self.extractors[key]
            elif any(domain in url for domain in ["sportzonline", "sportsonline"]):
                key = "sportsonline"
                proxies = GLOBAL_PROXIES
                if key not in self.extractors:
                    self.extractors[key] = SportsonlineExtractor(request_headers, proxies=proxies)
                return self.extractors[key]
            else:
                raise ExtractorError("Tipo di URL non supportato")
        except (NameError, TypeError) as e:
            raise ExtractorError(f"Estrattore non disponibile - modulo mancante: {e}")

    async def handle_proxy_request(self, request):
        """Gestisce le richieste proxy principali"""
        extractor = None
        try:
            target_url = request.query.get('url')
            # Recuperiamo la key per passarla ai link riscritti
            api_key = request.query.get('key') 
            
            force_refresh = request.query.get('force', 'false').lower() == 'true'
            if not target_url:
                return web.Response(text="Parametro 'url' mancante", status=400)
            
            try:
                target_url = urllib.parse.unquote(target_url)
            except:
                pass
                
            log_message = f"Richiesta proxy per URL: {target_url}"
            if force_refresh:
                log_message += " (Refresh forzato)"
            logger.info(log_message)
            
            extractor = await self.get_extractor(target_url, dict(request.headers))
            
            try:
                result = await extractor.extract(target_url, force_refresh=force_refresh)
                stream_url = result["destination_url"]
                stream_headers = result.get("request_headers", {})
                
                for param_name, param_value in request.query.items():
                    if param_name.startswith('h_'):
                        header_name = param_name[2:]
                        stream_headers[header_name] = param_value
                
                logger.info(f"Stream URL risolto: {stream_url}")
                # Passiamo api_key alla funzione proxy
                return await self._proxy_stream(request, stream_url, stream_headers, api_key)
            except ExtractorError as e:
                logger.warning(f"Estrazione fallita, tento di nuovo: {e}")
                result = await extractor.extract(target_url, force_refresh=True)
                stream_url = result["destination_url"]
                stream_headers = result.get("request_headers", {})
                logger.info(f"Stream URL risolto dopo refresh: {stream_url}")
                return await self._proxy_stream(request, stream_url, stream_headers, api_key)
            
        except Exception as e:
            restarting = False
            extractor_name = "sconosciuto"
            if DLHDExtractor and isinstance(extractor, DLHDExtractor):
                restarting = True
                extractor_name = "DLHDExtractor"
            elif VavooExtractor and isinstance(extractor, VavooExtractor):
                restarting = True
                extractor_name = "VavooExtractor"

            if restarting:
                logger.critical(f"❌ Errore critico con {extractor_name}: {e}. Riavvio...")
                await asyncio.sleep(1)
                os._exit(1)

            logger.exception(f"Errore nella richiesta proxy: {str(e)}")
            return web.Response(text=f"Errore proxy: {str(e)}", status=500)

    async def handle_key_request(self, request):
        key_url = request.query.get('key_url')
        
        if not key_url:
            return web.Response(text="Missing key_url parameter", status=400)
        
        try:
            try:
                key_url = urllib.parse.unquote(key_url)
            except:
                pass
                
            headers = {}
            for param_name, param_value in request.query.items():
                if param_name.startswith('h_'):
                    header_name = param_name[2:].replace('_', '-')
                    headers[header_name] = param_value

            logger.info(f"🔑 Fetching AES key from: {key_url}")
            
            proxy_list = GLOBAL_PROXIES
            original_channel_url = request.query.get('original_channel_url')

            if "newkso.ru" in key_url or (original_channel_url and any(domain in original_channel_url for domain in ["daddylive", "dlhd"])):
                proxy_list = DLHD_PROXIES or GLOBAL_PROXIES
            elif original_channel_url and "vavoo.to" in original_channel_url:
                proxy_list = VAVOO_PROXIES or GLOBAL_PROXIES
            
            proxy = random.choice(proxy_list) if proxy_list else None
            connector_kwargs = {}
            if proxy:
                connector_kwargs['proxy'] = proxy
            
            timeout = ClientTimeout(total=30)
            async with ClientSession(timeout=timeout) as session:
                async with session.get(key_url, headers=headers, **connector_kwargs) as resp:
                    if resp.status == 200:
                        key_data = await resp.read()
                        return web.Response(
                            body=key_data,
                            content_type="application/octet-stream",
                            headers={
                                "Access-Control-Allow-Origin": "*",
                                "Cache-Control": "no-cache, no-store, must-revalidate"
                            }
                        )
                    else:
                        logger.error(f"❌ Key fetch failed: {resp.status}")
                        try:
                            url_param = request.query.get('original_channel_url')
                            if url_param:
                                extractor = await self.get_extractor(url_param, {})
                                if hasattr(extractor, 'invalidate_cache_for_url'):
                                    await extractor.invalidate_cache_for_url(url_param)
                        except Exception:
                            pass
                        return web.Response(text=f"Key fetch failed: {resp.status}", status=resp.status)
                        
        except Exception as e:
            logger.error(f"❌ Error fetching AES key: {str(e)}")
            return web.Response(text=f"Key error: {str(e)}", status=500)

    async def handle_ts_segment(self, request):
        """Gestisce richieste per segmenti .ts"""
        try:
            segment_name = request.match_info.get('segment')
            base_url = request.query.get('base_url')
            
            if not base_url:
                return web.Response(text="Base URL mancante", status=400)
            
            base_url = urllib.parse.unquote(base_url)
            
            if base_url.endswith('/'):
                segment_url = f"{base_url}{segment_name}"
            else:
                segment_url = f"{base_url.rsplit('/', 1)[0]}/{segment_name}"
            
            return await self._proxy_segment(request, segment_url, {
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "referer": base_url
            }, segment_name)
            
        except Exception as e:
            logger.error(f"Errore nel proxy segmento .ts: {str(e)}")
            return web.Response(text=f"Errore segmento: {str(e)}", status=500)

    async def _proxy_segment(self, request, segment_url, stream_headers, segment_name):
        try:
            headers = dict(stream_headers)
            for header in ['range', 'if-none-match', 'if-modified-since']:
                if header in request.headers:
                    headers[header] = request.headers[header]
            
            proxy = random.choice(GLOBAL_PROXIES) if GLOBAL_PROXIES else None
            connector_kwargs = {}
            if proxy:
                connector_kwargs['proxy'] = proxy

            timeout = ClientTimeout(total=60, connect=30)
            async with ClientSession(timeout=timeout) as session:
                async with session.get(segment_url, headers=headers, **connector_kwargs) as resp:
                    response_headers = {}
                    for header in ['content-type', 'content-length', 'content-range', 
                                 'accept-ranges', 'last-modified', 'etag']:
                        if header in resp.headers:
                            response_headers[header] = resp.headers[header]
                    
                    response_headers['Content-Type'] = 'video/MP2T'
                    response_headers['Content-Disposition'] = f'attachment; filename="{segment_name}"'
                    response_headers['Access-Control-Allow-Origin'] = '*'
                    
                    response = web.StreamResponse(status=resp.status, headers=response_headers)
                    await response.prepare(request)
                    async for chunk in resp.content.iter_chunked(8192):
                        await response.write(chunk)
                    await response.write_eof()
                    return response
        except Exception as e:
            logger.error(f"Errore nel proxy del segmento: {str(e)}")
            return web.Response(text=f"Errore segmento: {str(e)}", status=500)

    async def _proxy_stream(self, request, stream_url, stream_headers, api_key=None):
        """Effettua il proxy dello stream. Supporta la propagazione della api_key."""
        try:
            headers = dict(stream_headers)
            for header in ['range', 'if-none-match', 'if-modified-since']:
                if header in request.headers:
                    headers[header] = request.headers[header]
            
            proxy = random.choice(GLOBAL_PROXIES) if GLOBAL_PROXIES else None
            connector_kwargs = {}
            if proxy:
                connector_kwargs['proxy'] = proxy

            timeout = ClientTimeout(total=60, connect=30)
            async with ClientSession(timeout=timeout) as session:
                async with session.get(stream_url, headers=headers, **connector_kwargs) as resp:
                    content_type = resp.headers.get('content-type', '')
                    
                    # MANIFEST HLS
                    if 'mpegurl' in content_type or stream_url.endswith('.m3u8') or (stream_url.endswith('.css') and 'newkso.ru' in stream_url):
                        manifest_content = await resp.text()
                        scheme = request.headers.get('X-Forwarded-Proto', request.scheme)
                        host = request.headers.get('X-Forwarded-Host', request.host)
                        proxy_base = f"{scheme}://{host}"
                        original_channel_url = request.query.get('url', '')
                        
                        # Passiamo api_key alla riscrittura
                        rewritten_manifest = await self._rewrite_manifest_urls(
                            manifest_content, stream_url, proxy_base, headers, original_channel_url, api_key
                        )
                        
                        return web.Response(
                            text=rewritten_manifest,
                            headers={
                                'Content-Type': 'application/vnd.apple.mpegurl',
                                'Content-Disposition': 'attachment; filename="stream.m3u8"',
                                'Access-Control-Allow-Origin': '*',
                                'Cache-Control': 'no-cache'
                            }
                        )
                    
                    # MANIFEST DASH
                    elif 'dash+xml' in content_type or stream_url.endswith('.mpd'):
                        manifest_content = await resp.text()
                        scheme = request.headers.get('X-Forwarded-Proto', request.scheme)
                        host = request.headers.get('X-Forwarded-Host', request.host)
                        proxy_base = f"{scheme}://{host}"
                        
                        # Passiamo api_key alla riscrittura
                        rewritten_manifest = self._rewrite_mpd_manifest(manifest_content, stream_url, proxy_base, headers, api_key)
                        
                        return web.Response(
                            text=rewritten_manifest,
                            headers={
                                'Content-Type': 'application/dash+xml',
                                'Content-Disposition': 'attachment; filename="stream.mpd"',
                                'Access-Control-Allow-Origin': '*',
                                'Cache-Control': 'no-cache'
                            })
                    
                    # STREAMING DIRETTO
                    response_headers = {}
                    for header in ['content-type', 'content-length', 'content-range', 
                                 'accept-ranges', 'last-modified', 'etag']:
                        if header in resp.headers:
                            response_headers[header] = resp.headers[header]
                    
                    response_headers['Access-Control-Allow-Origin'] = '*'
                    
                    response = web.StreamResponse(status=resp.status, headers=response_headers)
                    await response.prepare(request)
                    async for chunk in resp.content.iter_chunked(8192):
                        await response.write(chunk)
                    await response.write_eof()
                    return response
                    
        except Exception as e:
            logger.error(f"Errore nel proxy dello stream: {str(e)}")
            return web.Response(text=f"Errore stream: {str(e)}", status=500)

    def _rewrite_mpd_manifest(self, manifest_content: str, base_url: str, proxy_base: str, stream_headers: dict, api_key=None) -> str:
        try:
            if 'xmlns' not in manifest_content:
                manifest_content = manifest_content.replace('<MPD', '<MPD xmlns="urn:mpeg:dash:schema:mpd:2011"', 1)

            root = ET.fromstring(manifest_content)
            ns = {'mpd': 'urn:mpeg:dash:schema:mpd:2011'}

            header_params = "".join([f"&h_{urllib.parse.quote(key)}={urllib.parse.quote(value)}" for key, value in stream_headers.items() if key.lower() in ['user-agent', 'referer', 'origin', 'authorization']])
            
            # Aggiungi la key se presente
            key_param = f"&key={api_key}" if api_key else ""

            def create_proxy_url(relative_url):
                absolute_url = urljoin(base_url, relative_url)
                encoded_url = urllib.parse.quote(absolute_url, safe='')
                return f"{proxy_base}/proxy/manifest.m3u8?url={encoded_url}{header_params}{key_param}"

            for template_tag in root.findall('.//mpd:SegmentTemplate', ns):
                for attr in ['media', 'initialization']:
                    if template_tag.get(attr):
                        template_tag.set(attr, create_proxy_url(template_tag.get(attr)))
            
            for seg_url_tag in root.findall('.//mpd:SegmentURL', ns):
                if seg_url_tag.get('media'):
                    seg_url_tag.set('media', create_proxy_url(seg_url_tag.get('media')))

            return ET.tostring(root, encoding='unicode', method='xml')
        except Exception as e:
            logger.error(f"❌ Errore riscrittura MPD: {e}")
            return manifest_content

    async def _rewrite_manifest_urls(self, manifest_content: str, base_url: str, proxy_base: str, stream_headers: dict, original_channel_url: str = '', api_key=None) -> str:
        lines = manifest_content.split('\n')
        rewritten_lines = []
        
        # Logica VixSrc
        is_vixsrc_stream = False
        try:
            original_request_url = stream_headers.get('referer', base_url)
            extractor = await self.get_extractor(original_request_url, {})
            if hasattr(extractor, 'is_vixsrc') and extractor.is_vixsrc:
                is_vixsrc_stream = True
        except Exception:
            pass

        if is_vixsrc_stream:
            streams = []
            for i, line in enumerate(lines):
                if line.startswith('#EXT-X-STREAM-INF:'):
                    bandwidth_match = re.search(r'BANDWIDTH=(\d+)', line)
                    if bandwidth_match:
                        bandwidth = int(bandwidth_match.group(1))
                        streams.append({'bandwidth': bandwidth, 'inf': line, 'url': lines[i+1]})
            
            if streams:
                highest_quality_stream = max(streams, key=lambda x: x['bandwidth'])
                rewritten_lines.append('#EXTM3U')
                for line in lines:
                    if line.startswith('#EXT-X-MEDIA:') or line.startswith('#EXT-X-STREAM-INF:') or (line and not line.startswith('#')):
                        continue 
                rewritten_lines.extend([line for line in lines if line.startswith('#EXT-X-MEDIA:')])
                rewritten_lines.append(highest_quality_stream['inf'])
                rewritten_lines.append(highest_quality_stream['url'])
                return '\n'.join(rewritten_lines)

        header_params = "".join([f"&h_{urllib.parse.quote(key)}={urllib.parse.quote(value)}" for key, value in stream_headers.items() if key.lower() in ['user-agent', 'referer', 'origin', 'authorization']])
        
        # Aggiungi la key se presente
        key_param = f"&key={api_key}" if api_key else ""

        for line in lines:
            line = line.strip()
            
            if line.startswith('#EXT-X-KEY:') and 'URI=' in line:
                uri_start = line.find('URI="') + 5
                uri_end = line.find('"', uri_start)
                if uri_start > 4 and uri_end > uri_start:
                    original_key_url = line[uri_start:uri_end]
                    absolute_key_url = urljoin(base_url, original_key_url)
                    encoded_key_url = urllib.parse.quote(absolute_key_url, safe='')
                    encoded_original_channel_url = urllib.parse.quote(original_channel_url, safe='')
                    
                    # Aggiungiamo key_param anche qui
                    proxy_key_url = f"{proxy_base}/key?key_url={encoded_key_url}&original_channel_url={encoded_original_channel_url}"
                    
                    key_header_params = "".join(
                        [f"&h_{urllib.parse.quote(key)}={urllib.parse.quote(value)}" 
                         for key, value in stream_headers.items() if key.lower() in ['user-agent', 'referer', 'origin', 'authorization']]
                    )
                    proxy_key_url += key_header_params + key_param # <-- KEY AGGIUNTA
                    
                    new_line = line[:uri_start] + proxy_key_url + line[uri_end:]
                    rewritten_lines.append(new_line)
                else:
                    rewritten_lines.append(line)
            
            elif line.startswith('#EXT-X-MEDIA:') and 'URI=' in line:
                uri_start = line.find('URI="') + 5
                uri_end = line.find('"', uri_start)
                if uri_start > 4 and uri_end > uri_start:
                    original_media_url = line[uri_start:uri_end]
                    absolute_media_url = urljoin(base_url, original_media_url)
                    encoded_media_url = urllib.parse.quote(absolute_media_url, safe='')
                    # Aggiungiamo key_param
                    proxy_media_url = f"{proxy_base}/proxy/manifest.m3u8?url={encoded_media_url}{header_params}{key_param}"
                    new_line = line[:uri_start] + proxy_media_url + line[uri_end:]
                    rewritten_lines.append(new_line)
                else:
                    rewritten_lines.append(line)

            elif line and not line.startswith('#'):
                absolute_url = urljoin(base_url, line) if not line.startswith('http') else line
                encoded_url = urllib.parse.quote(absolute_url, safe='')
                # Aggiungiamo key_param
                proxy_url = f"{proxy_base}/proxy/manifest.m3u8?url={encoded_url}{header_params}{key_param}"
                rewritten_lines.append(proxy_url)

            else:
                rewritten_lines.append(line)
        
        return '\n'.join(rewritten_lines)

    async def handle_playlist_request(self, request):
        if not self.playlist_builder:
            return web.Response(text="❌ Playlist Builder non disponibile", status=503)
            
        try:
            url_param = request.query.get('url')
            if not url_param: return web.Response(text="Parametro 'url' mancante", status=400)
            
            playlist_definitions = [def_.strip() for def_ in url_param.split(';') if def_.strip()]
            
            scheme = request.headers.get('X-Forwarded-Proto', request.scheme)
            host = request.headers.get('X-Forwarded-Host', request.host)
            base_url = f"{scheme}://{host}"
            
            async def generate_response():
                async for line in self.playlist_builder.async_generate_combined_playlist(
                    playlist_definitions, base_url
                ):
                    yield line.encode('utf-8')
            
            response = web.StreamResponse(
                status=200,
                headers={
                    'Content-Type': 'application/vnd.apple.mpegurl',
                    'Content-Disposition': 'attachment; filename="playlist.m3u"',
                    'Access-Control-Allow-Origin': '*'
                }
            )
            await response.prepare(request)
            async for chunk in generate_response():
                await response.write(chunk)
            await response.write_eof()
            return response
            
        except Exception as e:
            logger.error(f"Errore playlist handler: {str(e)}")
            return web.Response(text=f"Errore: {str(e)}", status=500)

    def _read_template(self, filename: str) -> str:
        template_path = os.path.join(os.path.dirname(__file__), 'templates', filename)
        with open(template_path, 'r', encoding='utf-8') as f:
            return f.read()

    async def handle_root(self, request):
        try:
            html_content = self._read_template('index.html')
            return web.Response(text=html_content, content_type='text/html')
        except Exception:
            return web.Response(text="<h1>EasyProxy Active</h1>", content_type='text/html')

    async def handle_builder(self, request):
        try:
            html_content = self._read_template('builder.html')
            return web.Response(text=html_content, content_type='text/html')
        except Exception:
            return web.Response(text="Builder UI not available", status=500)

    async def handle_info_page(self, request):
        try:
            html_content = self._read_template('info.html')
            return web.Response(text=html_content, content_type='text/html')
        except Exception:
            return web.Response(text="Info page not available", status=500)

    async def handle_options(self, request):
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
            'Access-Control-Allow-Headers': 'Range, Content-Type',
            'Access-Control-Max-Age': '86400'
        }
        return web.Response(headers=headers)

    async def handle_api_info(self, request):
        info = {"status": "online", "version": "2.5.0-secure"}
        return web.json_response(info)

    async def cleanup(self):
        try:
            for extractor in self.extractors.values():
                if hasattr(extractor, 'close'):
                    await extractor.close()
        except Exception as e:
            logger.error(f"Errore durante cleanup: {e}")

# --- Middleware di Protezione ---
@web.middleware
async def security_middleware(request, handler):
    # 1. Legge la password dalle variabili d'ambiente
    secret_key = os.getenv('AUTH_PASS')
    
    # Se non c'è password impostata su Render, lascia passare tutto
    if not secret_key:
        return await handler(request)

    # 2. Controlla se l'utente ha passato la chiave nell'URL (?key=...)
    user_key = request.query.get('key')

    # 3. Se la chiave è corretta, procedi
    if user_key == secret_key:
        return await handler(request)
    
    # 4. Eccezioni: permetti la Home Page e Favicon per capire se il server è acceso
    if request.path == "/" or request.path == "/favicon.ico" or request.path == "/info":
         # Opzionale: se vuoi vedere la home anche senza password
         # return await handler(request)
         # Per ora mostriamo un messaggio di avviso
         pass

    if request.path == "/" or request.path == "/favicon.ico":
         return web.Response(text="EasyProxy è attivo e protetto. Aggiungi ?key=PASSWORD ai tuoi link.")

    # 5. Blocca tutto il resto
    return web.Response(text="⛔ Accesso Negato: Password (key) mancante o errata.", status=403)


# --- Logica di Avvio ---
def create_app():
    proxy = HLSProxy()
    
    # Aggiungiamo il middleware di sicurezza qui
    app = web.Application(middlewares=[security_middleware])
    
    app.router.add_get('/', proxy.handle_root)
    app.router.add_get('/builder', proxy.handle_builder)
    app.router.add_get('/info', proxy.handle_info_page)
    app.router.add_get('/api/info', proxy.handle_api_info)
    app.router.add_get('/key', proxy.handle_key_request)
    app.router.add_get('/proxy/manifest.m3u8', proxy.handle_proxy_request)
    app.router.add_get('/playlist', proxy.handle_playlist_request)
    app.router.add_get('/segment/{segment}', proxy.handle_ts_segment)
    
    app.router.add_route('OPTIONS', '/{tail:.*}', proxy.handle_options)
    
    async def cleanup_handler(app):
        await proxy.cleanup()
    app.on_cleanup.append(cleanup_handler)
    
    return app

app = create_app()

def main():
    web.run_app(app, host='0.0.0.0', port=7860)

if __name__ == '__main__':
    main()
