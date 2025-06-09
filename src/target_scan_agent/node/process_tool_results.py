from target_scan_agent.state import TargetScanState, TargetScan


class ProcessToolResultNode:

    def process_tool_results(self, state: TargetScanState):
        messages = state["messages"]
        new_results = []

        for msg in reversed(messages):
            if hasattr(msg, "type") and msg.type == "tool":
                scan_result = TargetScan(
                    scan_result=f"Tool: {msg.name}\nResult: {msg.content}"
                )
                new_results.append(scan_result)
            else:
                break

        return {"results": list(reversed(new_results))}
