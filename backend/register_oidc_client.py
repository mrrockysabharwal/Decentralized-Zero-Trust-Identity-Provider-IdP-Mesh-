
from backend.oidc.service import register_client

register_client(
    client_id="trustmesh-demo-client",
    redirect_uris=["http://localhost:3000/callback"],
)

print("OIDC demo client registered successfully.")
