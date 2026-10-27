"""
reinvent-harness-poc

The agent harness you own on AWS for regulated industries (re:Invent 2026
COM321). Seven rails, in the talk's order; each answers one regulator
question:

  1. Bit             permission gate          permission_gate.py
     "Who allowed this tool call?"
  2. Blinkers        tool and tenant scope    tenant_gate.py
     "What can the agent see?"
  3. Reins           named-human approval     raci_gate.py
     "Whose name is on this action?"
  4. Hoofprints      hash-chained audit       audit.py
     "What happened, and can you prove it?"
  5. Ground-driving  eval gate                eval_gate.py
     "Does the new version pass the old tests?"
  6. Stall           isolated runtime         sandbox.py
     "Where does AI-written code run?"
  7. Breeching       brakes                   checkpoint.py + pipeline.py
     "How does it stop, and resume?"

On AgentCore: agentcore.py builds a live AgentCore harness, Gateway and
Policy engine and runs rails 1 and 2 as the harness's before_tool_call hook
(agentcore_lambdas.py), with every decision on the rail-4 chain.

Supporting modules: observability.py (spans), guardrails.py (Bedrock
Guardrails), agent.py (a local Bedrock converse tool-use loop).

The rails are generalized from a production regulated-compliance platform.
See README.md for what AWS covers and what you still own.
"""

__version__ = "0.5.0"
