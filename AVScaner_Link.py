import asyncio
import datetime
import os
import random
import re
import ssl
import time
from asyncio import Queue
from typing import Tuple, Optional, Union

import aiohttp
import chardet
from aiohttp import ClientConnectorCertificateError, ClientSSLError
from aiohttp import ClientSession

from handlers.file_handler import read_file_to_queue, read_file_to_list, write_to_file, load_patterns
from handlers.parse_arguments import parse_arguments
from handlers.user_agent import USER_AGENTS
from handlers.utils import C, timer_decorator, limit_rate_decorator

PARSE_ARGS = parse_arguments()

INPUT = PARSE_ARGS.input
OUTPUT = PARSE_ARGS.output
PAYLOADS = PARSE_ARGS.payloads
ANSWERS = PARSE_ARGS.answers
CALL_LIMIT_PER_SECOND = PARSE_ARGS.concurrency
TIMEOUT = PARSE_ARGS.timeout
VERBOSE = PARSE_ARGS.verbose
URL_ENCODE = PARSE_ARGS.url_encode
PROXY = PARSE_ARGS.proxy


async def generate_payload_urls(link: str, payload_patterns: list[str]):
    scheme = link.replace('https://', 'http://')
    base_url = scheme.split('=')[0]
    links = [f"{base_url}={payload}" for payload in payload_patterns]
    return links


@limit_rate_decorator(calls_limit=CALL_LIMIT_PER_SECOND, timeout=1)
async def make_request(url: str, session: ClientSession) -> Tuple[str, Optional[Union[int, None]], Optional[str]]:
    proxy_url = PROXY if PROXY else None
    user_agent = random.choice(USER_AGENTS)
    headers = {'User-Agent': user_agent}

    scheme = url.replace('https://', 'http://')

    print(f'{C.blue}[+] ==> start perform: {url}{C.norm}')
    # await asyncio.sleep(random.randint(2, 10))
    await asyncio.sleep(5)

    return url, "response data"

async def create_request_tasks(urls_with_payload: list[str], session):
    tasks = {}
    for url in urls_with_payload:
        task = make_request(url, session)
        tasks[task] = url

    return tasks


async def process_link(link: str, payload_patterns: list[str], answer_patterns: re.Pattern, session: ClientSession):
    urls_with_payload = await generate_payload_urls(link, payload_patterns)
    total_urls = len(urls_with_payload)

    index = 0
    while index < total_urls:
        batch_urls = urls_with_payload[index:index + CALL_LIMIT_PER_SECOND]
        tasks = await create_request_tasks(batch_urls, session)
        print(f"{len(tasks)} {datetime.datetime.now()}")

        # Ждём завершения только CALL_LIMIT_PER_SECOND тасков
        for completed_task in asyncio.as_completed(tasks.keys()):
            url, result = await completed_task
            print(f'{C.green}[-] <== complete perform: {url}{C.norm}')

        index += CALL_LIMIT_PER_SECOND


async def handle_queue(link_queue: Queue, payload_patterns: list[str], answer_patterns: re.Pattern, session: ClientSession):
    while True:
        link = await link_queue.get()

        try:
            await process_link(link, payload_patterns, answer_patterns, session)
        except Exception as e:
            print(f'{C.red}[!] Error in handle_queue: {e}{C.norm}')
        finally:
            link_queue.task_done()


async def cancel_tasks(tasks: list[asyncio.Task]):
    for task in tasks:
        if not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


@timer_decorator
async def main():
    link_queue = asyncio.Queue(maxsize=100)

    payload_patterns = await read_file_to_list(PAYLOADS)
    answer_patterns = await load_patterns(ANSWERS)

    producer = asyncio.create_task(read_file_to_queue(INPUT, link_queue))

    timeout_for_all_requests = aiohttp.ClientTimeout(total=TIMEOUT)
    async with (aiohttp.ClientSession(
                                    connector=aiohttp.TCPConnector(limit=100, ssl=False, keepalive_timeout=30),
                                    timeout=timeout_for_all_requests)
                                    as session):

        consumers = [asyncio.create_task(handle_queue(link_queue=link_queue,
                                                      payload_patterns=payload_patterns,
                                                      answer_patterns=answer_patterns,
                                                      session=session)) for _ in range(20)]

        await asyncio.gather(producer)
        await link_queue.join()

        await cancel_tasks(consumers)
        await asyncio.gather(*consumers, return_exceptions=True)


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"{C.red} [!] Program interrupted by user. Exiting...{C.norm}")
    except Exception as e:
        print(f"{C.red}[!] Unexpected error: {e}{C.norm}")
