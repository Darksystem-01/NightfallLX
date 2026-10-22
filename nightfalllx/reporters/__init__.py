"""Report writers for Markdown and JSON."""

from nightfalllx.reporters.json_reporter import write_json_report
from nightfalllx.reporters.markdown import write_markdown_report

__all__ = ["write_markdown_report", "write_json_report"]
