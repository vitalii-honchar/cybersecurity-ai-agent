from target_scan_agent.state.state import TargetScanState
from langchain_core.messages import SystemMessage, BaseMessage
from langchain_core.runnables import Runnable
from langchain_core.language_models import LanguageModelInput
from dataclasses import dataclass

assistant_system_prompt = """You are a persistent security expert specialized in comprehensive web application vulnerability scanning.
You will be provided with a target URL and a description. Your task is to thoroughly analyze the target 
using MULTIPLE scanning approaches and techniques until you find vulnerabilities or exhaust all options.

Target url: '{url}'
Target description: '{description}'

CRITICAL SCANNING METHODOLOGY:
1. Start with broad vulnerability scanning (nuclei with different template sets)
2. Perform reconnaissance (directory discovery, tech detection, port scanning)
3. Try manual HTTP probing for common vulnerabilities
4. Test different attack vectors and endpoints
5. Use multiple tools and approaches - don't stop after first negative result

PERSISTENCE RULES:
- If one scan finds nothing, try different template tags or severity levels
- Explore different endpoints (/admin, /api, /login, etc.)
- Test for common misconfigurations and exposed files
- A "no vulnerabilities found" result means try harder, not give up
- Always perform at least 3-5 different types of scans before concluding
- Local applications (localhost) often have intentional vulnerabilities for testing

DO NOT conclude "no vulnerabilities" until you've tried multiple scanning approaches."""


@dataclass
class AssistantNode:
    llm_with_tools: Runnable[LanguageModelInput, BaseMessage]

    def assistant(self, state: TargetScanState):
        target = state["target"]
        messages = state.get("messages", [])

        prompt = assistant_system_prompt.format(
            url=target.url, description=target.description
        )

        # Add scan context if we have previous tool results
        if len(state["results"]) > 0:
            prompt += f"\n\nYou have {20 - len(state['results'])} tool calls remaining. Use them wisely."

            # Add context from previous scans
            scan_summary = "\n".join(
                [
                    f"Previous scan {i+1}: {result.scan_result}..."
                    for i, result in enumerate(state["results"])
                    if result.scan_result
                ]
            )
            if scan_summary:
                prompt += f"\n\nPrevious scan results:\n{scan_summary}"

        # Include conversation history so LLM can see tool results
        all_messages = messages + [SystemMessage(prompt)]
        res = self.llm_with_tools.invoke(all_messages)

        return {"messages": [res]}
