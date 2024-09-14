import asyncio
import random
from dataclasses import dataclass
from typing import Optional
from asyncio import Queue
import aiohttp
import re
from handlers.file_handler import read_file_to_list, load_patterns, read_file_to_queue
from handlers.parse_arguments import parse_arguments
from handlers.utils import C, timer_decorator, limit_rate_decorator
from aiohttp import ClientConnectorCertificateError, ClientSSLError
from aiohttp import ClientSession
import aiofiles

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
    tid: str # tid = task_id

    async def perform(self, pool):
        print(f'{C.blue}[+] ==> start perform: {self.tid}{C.norm}')
        # _time = random.randint(1, 5)
        _time = 2
        await asyncio.sleep(_time)
        print(f'{C.green}[-] <== complete perform: {self.tid}, _time={_time}{C.norm}')


class Pool:
    def __init__(self, max_rate: int, interval: int = 1, concurrent_level: Optional[int] = None):
        self.max_rate = max_rate  # максимальное количество запросов
        self.interval = interval  # если мы передаем значения max_rate = 5 и interval = 1, в секунду может исполняться 5 запросов
        self.concurrent_level = concurrent_level  # обозначает допустимое количество параллельных запросов
        self.is_running = False
        self._queue = asyncio.Queue(maxsize=100)
        self._urls_with_payload_queue = asyncio.Queue(maxsize=100)
        self._scheduler_task: Optional[asyncio.Task] = None
        self._sem = asyncio.Semaphore(concurrent_level or max_rate)
        self._cuncurrent_workers = 0
        self._stop_event = asyncio.Event()

        self.content_list = []
        self.combined_pattern = None


    async def _worker(self, task: Task):
        async with self._sem:  # Мы занимаем наш Semaphore пока операции внутри кода не закончатся
            self._cuncurrent_workers += 1

            await task.perform(self)

            self._urls_with_payload_queue.task_done()  # это означает, что задачу мы выполнили
        self._cuncurrent_workers -= 1
        if not self.is_running and self._cuncurrent_workers == 0:
            self._stop_event.set()


    async def _scheduler(self):
        while self.is_running:

            link = await self._queue.get()
            await self.generate_payload_urls(link, self.content_list)

            for _ in range(self.max_rate):
                async with self._sem:  # И чтоб не сыпать задачами Semaphore добавим сюда
                    task = await self._urls_with_payload_queue.get()
                    # print(task)
                    asyncio.create_task(self._worker(Task(task)))

            await asyncio.sleep(self.interval)
            self._queue.task_done()


    def start(self):
        self.is_running = True
        self._scheduler_task = asyncio.create_task(self._scheduler())

    async def put(self, task):
        await self._queue.put(task)

    async def join(self):
        await self._queue.join()

    async def stop(self):
        self.is_running = False
        self._scheduler_task.cancel()
        if self._cuncurrent_workers != 0:
            await self._stop_event.wait()

# -----------------------------------------------------------
    async def put_urls_with_payload(self, task):
        await self._urls_with_payload_queue.put(task)

    async def join_urls_with_payload(self):
        await self._urls_with_payload_queue.join()

    async def generate_payload_urls(self, link: str, payload_patterns: list[str]):
        scheme = link.replace('https://', 'http://')
        base_url = scheme.split('=')[0]

        for payload in payload_patterns:
            # print(f"{base_url}={payload}")
            await self._urls_with_payload_queue.put(f"{base_url}={payload}")
            # print(f'Producer put  to the _urls_with_payload_queue, {self._urls_with_payload_queue}')


    async def read_file_to_queue(self, file_path: str):  # producer
        async with aiofiles.open(file_path, mode='r') as file:
            async for line in file:
                await self._queue.put(line.strip())
                # print(f'Producer put  to the queue, {self._queue}')


    async def read_file_to_list(self, file_path: str):
        async with aiofiles.open(file_path, mode='r') as file:
            async for line in file:
                self.content_list.append(line.strip())
                if len(self.content_list) % 1000 == 0:
                    await asyncio.sleep(0)
        print(
            f'{C.yellow}[*] Total number of payload variants per link: {C.bold_yellow}{len(self.content_list )}\n\n{C.norm}')
        # return self.content_list


    async def load_patterns(self, file_path):
        async with aiofiles.open(file_path, mode='r') as file:
            patterns = [line.strip() for line in await file.readlines()]

        self.combined_pattern = re.compile('|'.join(re.escape(pattern) for pattern in patterns))
        # return combined_pattern



async def start(pool):

    await pool.read_file_to_queue(INPUT)
    await pool.read_file_to_list(PAYLOADS)
    await pool.load_patterns(ANSWERS)

    # print(pool.content_list)
    # print(pool.combined_pattern)



    pool.start()
    await pool.join()  # краулер будет ждать до тех пор, пока очередь не опустеет async def join
    await pool.join_urls_with_payload()
    await pool.stop()  # после того, как внутри пула закончатся задачи, его нужно корректно остановить


def main():
    # Создаем новый цикл событий
    loop = asyncio.new_event_loop()
    # Устанавливаем его как текущий цикл
    asyncio.set_event_loop(loop)
    pool = Pool(CALL_LIMIT_PER_SECOND)

    try:
        # Запускаем корутину до завершения
        loop.run_until_complete(start(pool))
    except KeyboardInterrupt:
        loop.run_until_complete(pool.stop())
        # Закрываем цикл событий при прерывании
        loop.close()


if __name__ == '__main__':
    main()
