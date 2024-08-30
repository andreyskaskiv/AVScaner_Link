import asyncio
import os
import random
import urllib.parse
from asyncio import Queue

import aiohttp

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


async def generate_payload_urls(link, payload_patterns):
    scheme = link.replace('https://', 'http://')
    base_url = scheme.split('=')[0]
    links = [f"{base_url}={payload}" for payload in payload_patterns]
    return links


@limit_rate_decorator(calls_limit=CALL_LIMIT_PER_SECOND, timeout=1)
async def make_request(url, session):
    proxy = PROXY if PROXY else None

    user_agent = random.choice(USER_AGENTS)
    headers = {'User-Agent': user_agent}

    url = urllib.parse.quote(url, safe=':/?=&') if URL_ENCODE else url
    try:
        async with session.get(url, headers=headers, proxy=proxy) as response:
            html = await response.text()
            return url, response.status, html

    except Exception as e:
        print(f'{C.red}[!] Error in make_request for {url}: {e}{C.norm}')
        return url, None, None


async def analyze_response(url, status, html, answer_patterns):
    output_folder = OUTPUT
    os.makedirs(output_folder, exist_ok=True)

    if status == 200 and answer_patterns.search(html):
        print(f'{C.bold_green}[+] URL: {url} | Status: {status} {C.norm}')

        output_file = f'{output_folder}/vulnerable_links.txt'
        await write_to_file(f'URL: {url} | Status: {status}', output_file)

    elif status == 403 and VERBOSE == 'v':
        print(f'{C.norm}[-] URL: {url} | Status: {C.bold_red}{status} {C.norm}')

        output_file = f'{output_folder}/403_links.txt'
        await write_to_file(f'URL: {url} | Status: {status}', output_file)

    elif status == 429 and VERBOSE == 'v':
        print(f'{C.red}[-] Too many requests, URL: {url} | Status: {C.bold_red}{status} {C.norm}')

        output_file = f'{output_folder}/429_links.txt'
        await write_to_file(f'URL: {url} | Status: {status}', output_file)

    elif status != 200 and VERBOSE == 'v':
        print(f'{C.bold_red}[-] URL: {url} | Status: {status} {C.norm}')

    elif VERBOSE == 'v':
        print(f'{C.norm}[-] URL: {url} | Status: {status} {C.norm}')


async def process_link(link, payload_patterns, answer_patterns, session):
    urls_with_payload = await generate_payload_urls(link, payload_patterns)

    tasks = {make_request(url, session): url for url in urls_with_payload}

    total_requests = len(tasks)
    completed_tasks = 0

    for completed_task in asyncio.as_completed(tasks.keys()):
        url, status, html = await completed_task

        completed_tasks += 1
        print(f"{C.norm}\r{completed_tasks}/{total_requests}{C.norm}  ", end='')

        if status is not None and html is not None:
            await analyze_response(url, status, html, answer_patterns)


async def handle_queue(link_queue: Queue, payload_patterns: list[str], answer_patterns, session):
    while True:
        link = await link_queue.get()

        try:
            await process_link(link, payload_patterns, answer_patterns, session)
        except Exception as e:
            print(f'{C.red}[!] Error in handle_queue: {e}{C.norm}')
        finally:
            link_queue.task_done()


@timer_decorator
async def main():
    link_queue = asyncio.Queue(maxsize=100)

    payload_patterns = await read_file_to_list(PAYLOADS)
    answer_patterns = await load_patterns(ANSWERS)

    producer = asyncio.create_task(read_file_to_queue(INPUT, link_queue))

    timeout_for_all_requests = aiohttp.ClientTimeout(total=TIMEOUT)
    async with aiohttp.ClientSession(timeout=timeout_for_all_requests) as session:
        consumers = [asyncio.create_task(handle_queue(link_queue=link_queue,
                                                      payload_patterns=payload_patterns,
                                                      answer_patterns=answer_patterns,
                                                      session=session)) for _ in range(20)]

        await asyncio.gather(producer)
        await link_queue.join()

        for consumer in consumers:
            consumer.cancel()
        await asyncio.gather(*consumers, return_exceptions=True)


if __name__ == '__main__':
    asyncio.run(main())
