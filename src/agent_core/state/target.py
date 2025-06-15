from pydantic import BaseModel, Field
from typing import Literal

TargetType = Literal["web"]


class Target(BaseModel):
    description: str = Field(description="A description of the target.")
    url: str = Field(description="The URL of the target.")
    type: TargetType = Field(description="The type of the target, e.g., 'web'.")

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")
