
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.oidc.service import register_client

register_client(
    client_id="trustmesh-demo-client",
    redirect_uris=["http://localhost:3000/callback", "http://127.0.0.1:3000/callback"],
)

print("OIDC demo client registered successfully.")
