import asyncio
import random
from dataclasses import dataclass
from typing import Optional
import aiofiles
import re

from handlers.parse_arguments import parse_arguments
from handlers.utils import C

PARSE_ARGS = parse_arguments()

INPUT = "input_data/crawled_final.txt"
OUTPUT = PARSE_ARGS.output
PAYLOADS = "wordlist/payloads_LFI.txt"
ANSWERS = "wordlist/answers_LFI.txt"
CALL_LIMIT_PER_SECOND = 3
TIMEOUT = 15
VERBOSE = None
URL_ENCODE = None
PROXY = PARSE_ARGS.proxy

@dataclass
class Task:
    url: str

    async def perform(self, pool):
        _time = random.randint(1, 5)
        print(f'{C.blue}[+] ==> start perform: {self.url}, _time={_time}{C.norm}')

        await asyncio.sleep(_time)
        print(f'{C.green}   [-] <== complete perform: {self.url}, _time={_time}{C.norm}')


class Pool:
    def __init__(self, max_rate: int, interval: int = 1, concurrent_level: Optional[int] = None):
        self.max_rate = max_rate
        self.interval = interval
        self.concurrent_level = concurrent_level
        self.is_running = False
        self._queue = asyncio.Queue(maxsize=100)
        self._urls_with_payload_queue = asyncio.Queue(maxsize=100)
        self._scheduler_task: Optional[asyncio.Task] = None
        self._scheduler_task_1: Optional[asyncio.Task] = None
        self._sem = asyncio.Semaphore(concurrent_level or max_rate)
        self._cuncurrent_workers = 0
        self._stop_event = asyncio.Event()

        self.content_list = []
        self.combined_pattern = None

    async def _worker(self, task: Task):
        async with self._sem:
            self._cuncurrent_workers += 1
            await task.perform(self)
            self._urls_with_payload_queue.task_done()  # это означает, что задачу мы выполнили
        self._cuncurrent_workers -= 1
        if not self.is_running and self._cuncurrent_workers == 0:
            self._stop_event.set()

    async def _scheduler(self):
        while self.is_running:
            for _ in range(self.max_rate):
                async with self._sem:
                    url = await self._urls_with_payload_queue.get()
                    # print(url)
                    asyncio.create_task(self._worker(Task(url)))
            await asyncio.sleep(self.interval)

    async def _scheduler_1(self):
        while self.is_running:
            link = await self._queue.get()
            await self.generate_payload_urls(link, self.content_list)
            self._queue.task_done()

    def start(self):
        self.is_running = True
        self._scheduler_task_1 = asyncio.create_task(self._scheduler_1())
        self._scheduler_task = asyncio.create_task(self._scheduler())

    async def put(self, task):
        await self._queue.put(task)

    async def join(self):
        await self._queue.join()

    async def join_urls_with_payload(self):
        await self._urls_with_payload_queue.join()

    async def stop(self):
        self.is_running = False
        self._scheduler_task_1.cancel()
        self._scheduler_task.cancel()
        if self._cuncurrent_workers != 0:
            await self._stop_event.wait()

    async def put_urls_with_payload(self, task):
        await self._urls_with_payload_queue.put(task)

    async def generate_payload_urls(self, link: str, payload_patterns: list[str]):
        scheme = link.replace('https://', 'http://')
        base_url = scheme.split('=')[0]

        for payload in payload_patterns:
            await self._urls_with_payload_queue.put(f"{base_url}={payload}")
            # print(f"{self._urls_with_payload_queue.qsize()} {payload}")
        # print(f"{self._urls_with_payload_queue}")

    async def read_file_to_queue(self, file_path: str):
        async with aiofiles.open(file_path, mode='r') as file:
            async for line in file:
                await self._queue.put(line.strip())

    async def read_file_to_list(self, file_path: str):
        async with aiofiles.open(file_path, mode='r') as file:
            async for line in file:
                self.content_list.append(line.strip())
        print(f'{C.yellow}[*] Total number of payload variants per link: {C.bold_yellow}{len(self.content_list)}\n\n{C.norm}')

    async def load_patterns(self, file_path):
        async with aiofiles.open(file_path, mode='r') as file:
            patterns = [line.strip() for line in await file.readlines()]

        self.combined_pattern = re.compile('|'.join(re.escape(pattern) for pattern in patterns))


async def start(pool):
    await pool.read_file_to_queue(INPUT)
    await pool.read_file_to_list(PAYLOADS)
    await pool.load_patterns(ANSWERS)


    pool.start()
    await pool.join()
    await pool.join_urls_with_payload()
    await pool.stop()


def main():
    # Создаем новый цикл событий
    loop = asyncio.new_event_loop()
    # Устанавливаем его как текущий цикл
    asyncio.set_event_loop(loop)
    pool = Pool(CALL_LIMIT_PER_SECOND)

    try:
        loop.run_until_complete(start(pool))
    except KeyboardInterrupt:
        loop.run_until_complete(pool.stop())
    finally:
        loop.close()


if __name__ == '__main__':
    main()
