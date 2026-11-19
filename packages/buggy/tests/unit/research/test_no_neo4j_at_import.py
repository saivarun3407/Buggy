import os
import subprocess
import sys


def test_research_tools_do_not_import_neo4j_at_module_load():
    # Base `pip install buggy` (no neo4j extra) must still import the
    # research tools. The neo4j driver is loaded lazily only when a
    # Neo4jStore is constructed (buggy/tools/research/neo4j_store.py).
    # A subprocess gives a clean module table independent of import order.
    code = (
        "import sys; "
        "import buggy.tools.research.tools; "
        "assert 'neo4j' not in sys.modules, sorted(m for m in sys.modules if 'neo4j' in m)"
    )
    # The KG integration fixtures put default BUGGY_NEO4J_* values into this
    # process's environment; with those set the agents build a KG store at
    # import. This test is about an unconfigured install, so start clean.
    env = {k: v for k, v in os.environ.items() if not k.startswith("BUGGY_NEO4J_")}
    subprocess.run([sys.executable, "-c", code], check=True, env=env)
