"""Budget-bounded live-test wrapper for benchmark_xbow (grok-4).

Caps sub-agent (operator) loops hard so a swarm+fanout run can't run away on a
paid model: the benchmark only lowers MAX_ITERATIONS on the LEAD instance, while
delegated sub-agents are fresh controllers that default to the class attribute.
Setting the CLASS attribute here bounds every child too. Args pass straight
through to benchmark_xbow.main().
"""
import os
import sys
from pathlib import Path

# Make both the project root and this tests/ dir importable regardless of cwd.
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.agent_controller import AgentController  # noqa: E402

# Hard cap for EVERY controller (lead + all sub-agents), so a fanned-out operator
# can't spend 50 grok-4 calls. The benchmark still sets the lead's instance cap
# from --max-iters on top of this.
AgentController.MAX_ITERATIONS = int(os.environ.get("LIVE_SUBAGENT_ITERS", "8"))

import benchmark_xbow as bx  # noqa: E402

if __name__ == "__main__":
    bx.main()
