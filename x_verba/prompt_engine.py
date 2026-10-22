"""X-Verba Prompt Engine — governed prompt generation. Coming in v0.6."""
from rich.console import Console
from rich.panel import Panel

console = Console()

NOT_IMPLEMENTED_MSG = """
This command is not yet available.

x-verba prompt will generate governance-informed prompts for AI coding
tools. Tell Claude, Copilot, or Cursor what the code must never do —
before they write a single line. The generated code will have governance
structure baked in from the first line.

The same Identity Key and governance vocabulary runs through the full
lifecycle: what was prompted → what was generated → what was scanned
→ what was compiled → what the runtime enforced.

Track progress: https://github.com/supersemantics/X-verba-CLI
"""


class PromptEngine:
    def generate(self, description=None, from_repo=None, domain="general"):
        console.print(Panel(
            NOT_IMPLEMENTED_MSG.strip(),
            title="[yellow]x-verba prompt — Not yet implemented[/yellow]",
            border_style="yellow",
        ))
        return {
            "status": "not_implemented",
            "message": "x-verba prompt is not yet available. See https://github.com/supersemantics/X-verba-CLI",
        }
