"""Built-in detection modules."""

from nightfalllx.core.registry import register
from nightfalllx.modules.lfi import LFIModule
from nightfalllx.modules.rce import RCEModule
from nightfalllx.modules.sqli import SQLiModule
from nightfalllx.modules.ssti import SSTIModule
from nightfalllx.modules.xss import XSSModule

register(LFIModule)
register(RCEModule)
register(SQLiModule)
register(SSTIModule)
register(XSSModule)

__all__ = ["LFIModule", "RCEModule", "SQLiModule", "SSTIModule", "XSSModule"]
