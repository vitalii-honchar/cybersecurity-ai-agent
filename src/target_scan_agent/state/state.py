import operator
from langgraph.graph import MessagesState
from pydantic import BaseModel, Field
from typing import Annotated


class Target(BaseModel):
    description: str = Field(description="A description of the target to be scanned.")
    url: str = Field(description="The URL of the target to be scanned.")


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


class TargetScanState(MessagesState):
    context: str
    target: Target
    results: Annotated[list[TargetScan], operator.add]
    summary: str | None
    call_count: int
