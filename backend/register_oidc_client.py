
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.oidc.service import register_client

register_client(
    client_id="trustmesh-client-app",
    redirect_uris=["http://localhost:3000/callback"],
)

register_client(
    client_id="trustmesh-demo-client",
    redirect_uris=["http://localhost:3000/callback"],
)

print("OIDC clients registered successfully.")

