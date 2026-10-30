"""Module base class and registry contract."""
from __future__ import annotations

from typing import List

from ..context import ScanContext
from ..findings import Finding
from ..target import Target
from ..utils import have_tool


class BaseModule:
    #: short identifier used in messages and registry
    name: str = "base"
    #: human readable description
    description: str = ""
    #: modes this module participates in (empty = explicit only)
    modes: tuple = ()
    #: external binaries that upgrade the module when present
    required_tools: tuple = ()

    def __init__(self, ctx: ScanContext) -> None:
        self.ctx = ctx
        self.log = ctx.logger
        self.ui = ctx.ui

    # ------------------------------------------------------------------
    @property
    def config(self):
        return self.ctx.config

    @property
    def http(self):
        return self.ctx.http

    def missing_tools(self) -> List[str]:
        return [tool for tool in self.required_tools if not have_tool(tool)]

    def enabled(self) -> bool:
        """A module is enabled when its optional external tools are available.

        Modules that have no external dependencies are always enabled.
        """
        if not self.required_tools:
            return True
        if not self.config.use_optional_tools:
            return False
        return not self.missing_tools()

    def applies(self, target: Target) -> bool:
        return True

    def run(self, target: Target) -> List[Finding]:  # pragma: no cover - abstract
        raise NotImplementedError

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<{self.__class__.__name__} name={self.name!r}>"
