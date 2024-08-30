import asyncio
from datetime import datetime


class C:
    norm = '\033[0m'
    blue = '\033[94m'
    bold_blue = '\033[1;94m'
    green = '\033[92m'
    bold_green = '\033[1;92m'
    red = '\033[91m'
    bold_red = '\033[1;91m'
    yellow = '\033[93m'
    bold_yellow = '\033[1;93m'
    cyan = '\033[96m'
    bold_cyan = '\033[1;96m'
    magenta = '\033[95m'
    bold_magenta = '\033[1;95m'
    white = '\033[97m'
    bold_white = '\033[1;97m'


def timer_decorator(func):
    async def wrapper(*args, **kwargs):
        start_time = datetime.now()
        print(f"\n{C.bold_white}[*] Starting @ {C.bold_magenta}{start_time.strftime('%H:%M:%S %Y-%m-%d')}{C.norm}")

        result = await func(*args, **kwargs)

        end_time = datetime.now()
        print(f"\n\n{C.bold_white}[*] Finished @ {C.bold_magenta}{end_time.strftime('%H:%M:%S %Y-%m-%d')}{C.norm}")
        print(f"{C.bold_white}[*] Duration: {C.bold_magenta}{end_time - start_time}{C.norm}\n\n")
        return result

    return wrapper


def limit_rate_decorator(calls_limit=20, timeout=1):
    def wrapper(coro):
        semaphore = asyncio.Semaphore(calls_limit)

        async def wait():
            try:
                await asyncio.sleep(timeout)
            finally:
                semaphore.release()

        async def inner_coro(*args, **kwargs):
            await semaphore.acquire()
            asyncio.create_task(wait())

            return await coro(*args, **kwargs)

        return inner_coro

    return wrapper
