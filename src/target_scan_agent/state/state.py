import operator
from langgraph.graph import MessagesState
from pydantic import BaseModel, Field
from typing import Annotated, Dict, Any
from datetime import timedelta


class Target(BaseModel):
    description: str = Field(description="A description of the target to be scanned.")
    url: str = Field(description="The URL of the target to be scanned.")

    def to_json(self) -> str:
        """Convert to JSON string for serialization."""
        return self.model_dump_json()

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode="json")


class TargetScan(BaseModel):
    name: str | None = Field(
        default=None,
        description="The name of the scan result, if applicable.",
    )
    severity: str | None = Field(
        default=None,
        description="The severity level of the scan result, if applicable.",
    )
    description: str | None = Field(
        default=None,
        description="A description of the scan result, including any vulnerabilities or insights found.",
    )
    possible_attacks: list[str] | None = Field(
        default=None,
        description="A list of possible attacks or vulnerabilities identified during the scan with command examples",
    )

    def to_json(self) -> str:
        """Convert to JSON string for serialization."""
        return self.model_dump_json()

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode="json")


class TargetScanOutput(BaseModel):
    summary: str | None = Field(
        default=None,
        description="A summary of the scan results, including any vulnerabilities or insights found.",
    )

    def to_json(self) -> str:
        """Convert to JSON string for serialization."""
        return self.model_dump_json()

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return self.model_dump(mode="json")


class ToolsCalls(BaseModel):
    nuclei_calls_count: int = Field(
        default=0,
        description="Number of nuclei scans performed.",
    )
    nuclei_calls_count_max: int = Field(
        default=3,
        description="Maximum number of nuclei scans allowed.",
    )

    ffuf_calls_count: int = Field(
        default=0,
        description="Number of ffuf directory scans performed.",
    )
    ffuf_calls_count_max: int = Field(
        default=3,
        description="Maximum number of ffuf directory scans allowed.",
    )

    curl_calls_count: int = Field(
        default=0,
        description="Number of curl commands executed.",
    )
    curl_calls_count_max: int = Field(
        default=20,
        description="Maximum number of curl commands allowed.",
    )


class TargetScanState(MessagesState):
    context: str
    target: Target
    tools_calls: ToolsCalls
    timeout: timedelta
    results: Annotated[list[TargetScan], operator.add]
    summary: str | None
    call_count: int
    max_calls: int
