import asyncio
import re

import aiofiles

from handlers.utils import C


class FileHandler:
    def __init__(self):
        self.payloads = []
        self.combined_pattern = None

    async def read_file_to_queue(self, file_path: str, queue: asyncio.Queue):
        async with aiofiles.open(file_path, mode='r') as file:
            async for line in file:
                await queue.put(line.strip())

    async def read_file_to_list(self, file_path: str):
        async with aiofiles.open(file_path, mode='r') as file:
            async for line in file:
                self.payloads.append(line.strip())
        print(
            f'{C.yellow}[*] Total number of payload variants per link: {C.bold_yellow}{len(self.payloads)}\n\n{C.norm}')

    async def load_patterns(self, file_path: str):
        async with aiofiles.open(file_path, mode='r') as file:
            patterns = [line.strip() for line in await file.readlines()]

        self.combined_pattern = re.compile('|'.join(re.escape(pattern) for pattern in patterns))

async def write_to_file(message: str, file_path: str):
    async with aiofiles.open(file_path, mode='a') as f:
        await f.write(message + '\n')
