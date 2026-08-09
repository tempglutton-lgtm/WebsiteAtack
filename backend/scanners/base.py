from abc import ABC, abstractmethod
from typing import Any, Optional

import aiohttp

class Scanner(ABC):
    name: str
    description: str

    @abstractmethod
    def applicable(self, endpoint: Any) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def run(self, endpoint: Any, session: Optional[aiohttp.ClientSession] = None) -> list[Any]:
        raise NotImplementedError

    @abstractmethod
    def return_findings(self) -> list[Any]:
        raise NotImplementedError
