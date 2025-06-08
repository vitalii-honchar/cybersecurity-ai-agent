# Cyber Security AI Agent

**Project Target:** learn LangGraph by building real world AI Agent

**Requirements:**
- Scan Web application or REST API to find most common vulnerabilities 
- Generate a report with vulnerabilities and potential places for improvements
- User enters URL in CLI and then AI Agent starts scanning web app
- Report shows in CLI stdout
- *Optional:* build simple web ui for this agent. Or instead of CLI build web ui. 

## System Design

## AI Agent Architecture

![AI Agent Architecture](/docs/ai-agent-architecture.png)

### Expert Agent Creation

![Expert Agent Creation](/docs/expert-agent-creation.png)


### Target Scan Agent
![Target Scan Agent](/docs/target-scan-agent.png)

### Penetration Agent

![Penetration Agent](/docs/penetration-agent.png)

### Summary Generation

![Summary Generation](/docs/summary-generation.png)

## AI Agent Patterns

- Mixture of Experts
- ReAct