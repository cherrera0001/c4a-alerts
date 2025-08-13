# src/sources/base.py
from typing import List, Dict, Any
class SourceAdapter:
    name: str
    async def fetch(self, client, limit:int=10) -> List[Dict[str,Any]]:
        raise NotImplementedError
