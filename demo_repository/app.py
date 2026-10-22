"""Small safe fixture for the Evalora mentoring-round demonstration."""


def submit_item(item):
    if not item:
        return {"ok": False, "error": "missing item"}
    return {"ok": True, "item": item}


def fetch_remote_value(url):
    # Deliberate harmless issue: no retry/timeout policy is declared here.
    return {"url": url}
