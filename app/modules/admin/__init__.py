"""
app/modules/admin/__init__.py — Admin Dashboard API Module (Module D)
=====================================================================
Owner  : Member 6 (Admin Dashboard)
Module : D — Admin Dashboard API
Branch : feature/admin-dashboard

Public exports for Member 1 (Core Backend) to wire into app/main.py:

    from app.modules.admin import admin_router
    app.include_router(admin_router, prefix="/api/v1")

Wire shared state at startup:

    import app.modules.admin.router as _admin_router_module
    _admin_router_module._shared_ledger    = ledger_instance
    _admin_router_module._credential_store = _credential_store_singleton
"""

from app.modules.admin.router import router as admin_router

__all__ = [
    "admin_router",
]
