import asyncio
import urllib.parse
from typing import Optional

from fetch_task import Task
from handlers.file_handler import FileHandler
from handlers.parse_arguments import parse_arguments
from handlers.utils import C


class Pool:
    def __init__(self, max_rate: int, payloads_encode: bool, interval: int = 1, concurrent_level: Optional[int] = None,
                 task_factory: Optional[callable] = None):

        self.max_rate = max_rate
        self.interval = interval
        self.concurrent_level = concurrent_level
        self.payloads_encode = payloads_encode
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
        self.detected = []

    async def _worker(self, task: Task) -> None:
        async with self._sem:
            self._cuncurrent_workers += 1

            url_detected = await task.perform(self)
            if url_detected is None:
                self._payloadUrls_queue.task_done()
                self._cuncurrent_workers -= 1
                return

            base_url = url_detected.split('=')[0]
            if base_url in self.detected:
                self._payloadUrls_queue.task_done()
                self._cuncurrent_workers -= 1
                return

            self.detected.append(base_url)
            self._payloadUrls_queue.task_done()
        self._cuncurrent_workers -= 1

        if not self.is_running and self._cuncurrent_workers == 0:
            self._stop_event.set()

    async def _scheduler_payloadUrls_queue(self) -> None:
        while self.is_running:
            tasks_created = False

            for _ in range(self.max_rate):
                async with self._sem:
                    url = await self._payloadUrls_queue.get()
                    base_url = url.split('=')[0]

                    if base_url in self.detected:
                        self._payloadUrls_queue.task_done()
                        continue

                    task = self.task_factory(url)
                    if task:
                        asyncio.create_task(self._worker(task))
                        tasks_created = True

            if tasks_created:
                await asyncio.sleep(self.interval)

    async def _scheduler_link_queue(self) -> None:
        while self.is_running:
            link = await self._link_queue.get()
            await self.generate_payload_urls(link, self.file_handler.payloads)
            self._link_queue.task_done()

    def start(self) -> None:
        self.is_running = True
        self._scheduler_task_link_queue = asyncio.create_task(self._scheduler_link_queue())
        self._scheduler_task_payloadUrls_queue = asyncio.create_task(self._scheduler_payloadUrls_queue())

    async def join_link_queue(self) -> None:
        await self._link_queue.join()

    async def join_payloadUrls_queue(self) -> None:
        await self._payloadUrls_queue.join()

    async def stop(self) -> None:
        self.is_running = False
        self._scheduler_task_link_queue.cancel()
        self._scheduler_task_payloadUrls_queue.cancel()
        if self._cuncurrent_workers != 0:
            await self._stop_event.wait()

    async def generate_payload_urls(self, link: str, payload_patterns: list[str]) -> None:
        scheme = link.replace('https://', 'http://')
        base_url = scheme.split('=')[0]

        for payload in payload_patterns:
            if self.payloads_encode:
                encoded_payload = urllib.parse.quote(payload, safe='')
            else:
                encoded_payload = payload

            await self._payloadUrls_queue.put(f"{base_url}={encoded_payload}")


async def start(pool, input_file, payloads_file, answers_file):
    await pool.file_handler.read_file_to_queue(input_file, pool._link_queue)
    await pool.file_handler.read_file_to_list(payloads_file)
    await pool.file_handler.load_patterns(answers_file)

    pool.start()

    await pool.join_link_queue()
    await pool.join_payloadUrls_queue()
    await pool.stop()


def task_factory(output_file: str, timeout: int, verbose: bool, proxy: Optional[str]) -> callable:
    def create_task(url):
        return Task(
            url=url,
            output_file=output_file,
            timeout=timeout,
            verbose=verbose,
            proxy=proxy
        )

    return create_task


def main(input_file: str,
         output_file: str,
         payloads_file: str,
         answers_file: str,
         call_limit_per_second: int,
         timeout: int,
         verbose: bool,
         payloads_encode: bool,
         proxy) -> None:

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    create_task = task_factory(output_file, timeout, verbose, proxy)
    pool = Pool(max_rate=call_limit_per_second, payloads_encode=payloads_encode, task_factory=create_task)

    try:
        loop.run_until_complete(start(pool, input_file, payloads_file, answers_file))
    except KeyboardInterrupt:
        print(f"{C.red} [!] Program interrupted by user. Exiting...{C.norm}")
        loop.run_until_complete(pool.stop())
    except Exception as e:
        print(f"{C.red}[!] Unexpected error: {e}{C.norm}")
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
        payloads_encode=PARSE_ARGS.payloads_encode,
        proxy=PARSE_ARGS.proxy,
    )
