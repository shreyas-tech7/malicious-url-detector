import sys
from pathlib import Path

# Make `ml/` importable so tests can `import features` the same way the
# training scripts and the serverless function do.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
