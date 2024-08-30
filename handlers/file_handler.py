import asyncio
from asyncio import Queue
import re
import aiofiles

from handlers.utils import C


async def read_file_to_queue(file_path: str, link_queue: Queue):  # producer
    async with aiofiles.open(file_path, mode='r') as file:
        async for line in file:
            await link_queue.put(line.strip())


async def read_file_to_list(file_path: str) -> list:
    content_list = []
    async with aiofiles.open(file_path, mode='r') as file:
        async for line in file:
            content_list.append(line.strip())
            if len(content_list) % 1000 == 0:
                await asyncio.sleep(0)

    print(f'{C.yellow}[*] Total number of payload variants per link: {C.bold_yellow}{len(content_list)}\n\n{C.norm}')
    return content_list


async def load_patterns(file_path):
    async with aiofiles.open(file_path, mode='r') as file:
        patterns = [line.strip() for line in await file.readlines()]

    combined_pattern = re.compile('|'.join(re.escape(pattern) for pattern in patterns))
    return combined_pattern


async def write_to_file(message: str, file_path: str):
    async with aiofiles.open(file_path, mode='a') as f:
        await f.write(message + '\n')
