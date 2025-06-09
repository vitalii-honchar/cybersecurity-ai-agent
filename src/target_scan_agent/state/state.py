import operator
from langgraph.graph import MessagesState
from pydantic import BaseModel, Field
from typing import Annotated


class Target(BaseModel):
    description: str = Field(description="A description of the target to be scanned.")
    url: str = Field(description="The URL of the target to be scanned.")


class TargetScan(BaseModel):
    scan_result: str | None = Field(
        default=None,
        description="The result of the target scan, including any vulnerabilities or insights found.",
    )


class TargetScanOutput(BaseModel):
    summary: str | None = Field(
        default=None,
        description="A summary of the scan results, including any vulnerabilities or insights found.",
    )


class TargetScanState(MessagesState):
    context: str
    target: Target
    results: Annotated[list[TargetScan], operator.add]
    summary: str | None
    call_count: int
