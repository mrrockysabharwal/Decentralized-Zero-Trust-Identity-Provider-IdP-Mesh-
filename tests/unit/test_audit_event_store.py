from app.modules.audit.event_store import AuditEventStore


def test_event_store_pseudonymizes_did_and_supports_filters(tmp_path):
    store = AuditEventStore(str(tmp_path / "events.sqlite3"))
    event = store.record(event_type="authentication", outcome="failure", severity="medium",
                         did="did:mesh:key:private-subject", reason="assertion_verification_failed")
    assert "private-subject" not in str(event)
    assert event["did_ref"].startswith("did#")
    rows, total = store.list_events(event_type="authentication", outcome="failure")
    assert total == 1
    assert rows[0]["event_id"] == event["event_id"]


def test_event_store_detail_and_counts_survive_reopen(tmp_path):
    path = str(tmp_path / "persistent-events.sqlite3")
    store = AuditEventStore(path)
    event = store.record(event_type="token_revocation", outcome="success", severity="low",
                         reason="owner_revoked_token")
    reopened = AuditEventStore(path)
    assert reopened.get_event(event["event_id"])["reason"] == "owner_revoked_token"
    assert reopened.counts()["token_revocation:success"] == 1


def test_event_store_paginates_and_orders_newest_first(tmp_path):
    store = AuditEventStore(str(tmp_path / "paged.sqlite3"))
    older = store.record(event_type="authentication", outcome="success", reason="first")
    newer = store.record(event_type="authentication", outcome="success", reason="second")
    rows, total = store.list_events(page=1, page_size=1)
    assert total == 2
    assert rows[0]["event_id"] == newer["event_id"]
    rows, _ = store.list_events(page=2, page_size=1)
    assert rows[0]["event_id"] == older["event_id"]
