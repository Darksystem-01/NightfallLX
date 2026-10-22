"""Built-in detection modules."""

from nightfalllx.modules.lfi import LFIModule
from nightfalllx.modules.rce import RCEModule
from nightfalllx.modules.sqli import SQLiModule
from nightfalllx.modules.xss import XSSModule

__all__ = ["LFIModule", "RCEModule", "SQLiModule", "XSSModule"]
