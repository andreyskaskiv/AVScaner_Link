import asyncio
from typing import Optional

from handlers.file_handler import FileHandler
from handlers.parse_arguments import parse_arguments
from task import Task


class Pool:
    def __init__(self, max_rate: int, interval: int = 1, concurrent_level: Optional[int] = None,
                 task_factory=None):

        self.max_rate = max_rate
        self.interval = interval
        self.concurrent_level = concurrent_level

        self.is_running = False
        self._link_queue = asyncio.Queue(maxsize=100)
        self._payloadUrls_queue = asyncio.Queue(maxsize=100)
        self._scheduler_task_link_queue: Optional[asyncio.Task] = None
        self._scheduler_task_payloadUrls_queue: Optional[asyncio.Task] = None
        self._sem = asyncio.Semaphore(concurrent_level or max_rate)
        self._cuncurrent_workers = 0
        self._stop_event = asyncio.Event()

        self.file_handler = FileHandler()

        self.task_factory = task_factory

    async def _worker(self, task: Task):
        async with self._sem:
            self._cuncurrent_workers += 1

            await task.perform(self)

            self._payloadUrls_queue.task_done()
        self._cuncurrent_workers -= 1
        if not self.is_running and self._cuncurrent_workers == 0:
            self._stop_event.set()

    async def _scheduler_payloadUrls_queue(self):
        while self.is_running:
            for _ in range(self.max_rate):
                async with self._sem:
                    url = await self._payloadUrls_queue.get()
                    task = self.task_factory(url)
                    asyncio.create_task(self._worker(task))
            await asyncio.sleep(self.interval)

    async def _scheduler_link_queue(self):
        while self.is_running:
            link = await self._link_queue.get()
            await self.generate_payload_urls(link, self.file_handler.payloads)
            self._link_queue.task_done()

    def start(self):
        self.is_running = True
        self._scheduler_task_link_queue = asyncio.create_task(self._scheduler_link_queue())
        self._scheduler_task_payloadUrls_queue = asyncio.create_task(self._scheduler_payloadUrls_queue())

    async def join_link_queue(self):
        await self._link_queue.join()

    async def join_payloadUrls_queue(self):
        await self._payloadUrls_queue.join()

    async def stop(self):
        self.is_running = False
        self._scheduler_task_link_queue.cancel()
        self._scheduler_task_payloadUrls_queue.cancel()
        if self._cuncurrent_workers != 0:
            await self._stop_event.wait()

    async def generate_payload_urls(self, link: str, payload_patterns: list[str]):
        scheme = link.replace('https://', 'http://')
        base_url = scheme.split('=')[0]

        for payload in payload_patterns:
            await self._payloadUrls_queue.put(f"{base_url}={payload}")


async def start(pool, input_file, payloads_file, answers_file):
    await pool.file_handler.read_file_to_queue(input_file, pool._link_queue)
    await pool.file_handler.read_file_to_list(payloads_file)
    await pool.file_handler.load_patterns(answers_file)

    pool.start()

    await pool.join_link_queue()
    await pool.join_payloadUrls_queue()
    await pool.stop()


def task_factory(output_file, timeout, verbose, url_encode, proxy):
    def create_task(url):
        return Task(
            url=url,
            output_file=output_file,
            timeout=timeout,
            verbose=verbose,
            url_encode=url_encode,
            proxy=proxy
        )

    return create_task


def main(input_file, output_file, payloads_file, answers_file, call_limit_per_second, timeout, verbose, url_encode,
         proxy):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    create_task = task_factory(output_file, timeout, verbose, url_encode, proxy)

    pool = Pool(max_rate=call_limit_per_second, task_factory=create_task)

    try:
        loop.run_until_complete(start(pool, input_file, payloads_file, answers_file))
    except KeyboardInterrupt:
        loop.run_until_complete(pool.stop())
    finally:
        loop.close()


if __name__ == '__main__':
    PARSE_ARGS = parse_arguments()

    main(
        input_file=PARSE_ARGS.input,
        output_file=PARSE_ARGS.output,
        payloads_file=PARSE_ARGS.payloads,
        answers_file=PARSE_ARGS.answers,
        call_limit_per_second=PARSE_ARGS.concurrency,
        timeout=PARSE_ARGS.timeout,
        verbose=PARSE_ARGS.verbose,
        url_encode=PARSE_ARGS.url_encode,
        proxy=PARSE_ARGS.proxy,
    )
