import sys
import os


def _ensure_agents_on_path() -> None:
    """Ensure agents module can be found when imported from backend.

    Refactor note: keep path setup in one place for maintainability.
    """
    root_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    if root_dir not in sys.path:
        sys.path.append(root_dir)
    agents_dir = os.path.join(root_dir, "agents")
    if agents_dir not in sys.path:
        sys.path.append(agents_dir)


_ensure_agents_on_path()

from agents.config_loader import load_config
from agents.agent_core import FunctionAnalysisAgent, MalwareAnalysisAgent
from agents.ghidra_client import GhidraClient
from agents.analysis_coordinator import AnalysisCoordinator


def create_coordinator() -> AnalysisCoordinator:
    config = load_config("agents/config.yaml")

    ghidra_client = GhidraClient(config=config)

    # Initialize agents (they load config internally in current implementation)
    func_agent = FunctionAnalysisAgent()
    malware_agent = MalwareAnalysisAgent()

    return AnalysisCoordinator(ghidra_client, func_agent, malware_agent)

