from app import submit_item


def test_submit_item():
    assert submit_item("demo")["ok"] is True
