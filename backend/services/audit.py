from backend.database.models import AuditEvent


def record_event(session, event_type, admin=None, outcome="success", details=None, **links):
    event = AuditEvent(
        actor_type="administrator" if admin else "system",
        administrator_id=admin.id if admin else None,
        event_type=event_type,
        outcome=outcome,
        details_json=details or {},
        **links,
    )
    session.add(event)
    return event