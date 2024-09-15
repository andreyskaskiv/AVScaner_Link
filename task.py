import os
import random
from dataclasses import dataclass
from typing import Optional

import aiohttp
import chardet
from aiohttp import ClientConnectorCertificateError, ClientSSLError

from handlers.user_agent import USER_AGENTS
from handlers.utils import C


@dataclass
class Task:
    url: str
    output_file: str
    timeout: int
    verbose: str
    url_encode: bool
    proxy: Optional[str]

    async def make_request(self, pool):
        timeout_for_all_requests = aiohttp.ClientTimeout(total=self.timeout)
        async with (aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(limit=100, ssl=False, keepalive_timeout=30),
                timeout=timeout_for_all_requests)
        as session):

            proxy_url = self.proxy if self.proxy else None
            user_agent = random.choice(USER_AGENTS)
            headers = {'User-Agent': user_agent}

            try:
                async with session.get(self.url, headers=headers, proxy=proxy_url, ssl=False) as response:
                    try:
                        raw_data = await response.read()
                        detected_encoding = chardet.detect(raw_data)['encoding']
                        html = raw_data.decode(detected_encoding,
                                               errors="ignore")

                        return self.url, response.status, html

                    except aiohttp.ClientPayloadError as e:
                        print(
                            f'{C.yellow}\n[!] Warning in make_request for {self.url}: {e}. Some data may be missing.{C.norm}')
                        return self.url, response.status, None

            except (ClientConnectorCertificateError, ClientSSLError) as ssl_error:
                print(f'{C.red}[!] SSL Error in make_request for {self.url}: {ssl_error}{C.norm}')
                return self.url, None, None

            except aiohttp.ClientError as e:
                print(f'{C.red}[!] HTTP Client Error in make_request for {self.url}: {e}{C.norm}')
                return self.url, None, None

            except Exception as e:
                print(f'{C.red}[!] Unexpected Error in make_request for {self.url} {e}{C.norm}')
                return self.url, None, None

    async def analyze_response(self, url: str, status: int, html: str, pool):
        output_folder = self.output_file
        os.makedirs(output_folder, exist_ok=True)

        if status == 200 and pool.file_handler.combined_pattern.search(html):
            print(f'{C.bold_green}[+] URL: {url} | Status: {status} {C.norm}')

            output_file = f'{output_folder}/vulnerable_links.txt'
            await pool.file_handler.write_to_file(f'URL: {url} | Status: {status}', output_file)

        elif status == 403 and self.verbose == 'v':
            print(f'{C.norm}[-] URL: {url} | Status: {C.bold_red}{status} {C.norm}')

            output_file = f'{output_folder}/403_links.txt'
            await pool.file_handler.write_to_file(f'URL: {url} | Status: {status}', output_file)

        elif status == 429 and self.verbose == 'v':
            print(f'{C.red}[-] Too many requests, URL: {url} | Status: {C.bold_red}{status} {C.norm}')

            output_file = f'{output_folder}/429_links.txt'
            await pool.file_handler.write_to_file(f'URL: {url} | Status: {status}', output_file)

        elif status != 200 and self.verbose == 'v':
            print(f'{C.bold_red}[-] URL: {url} | Status: {status} {C.norm}')

        elif self.verbose == 'v':
            print(f'{C.norm}[-] URL: {url} | Status: {status} {C.norm}')

    async def perform(self, pool):
        url, status, html = await self.make_request(pool)

        if status is not None and html is not None:
            await self.analyze_response(url, status, html, pool)
