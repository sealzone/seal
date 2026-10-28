"""An app uses a sealed secret through the enclave without ever holding it, through the SDK's
tunnel: HTTP, Postgres and Redis."""

from __future__ import annotations

import psycopg
import pytest
import redis

from world import PG_PASSWORD, REDIS_PASSWORD, SECRET, World, connect, get


def test_an_api_key_is_used_without_the_app_holding_it(world: World) -> None:
    blob = world.seal_with_cli(SECRET, world.upstream_url, "--format", "Bearer {key}")
    assert blob.startswith("seal1.acme.") and SECRET not in blob
    app = world.client()
    bodies, keys = [], []

    # Tunnel: two calls on one kept-alive connection with an extend in between, then close.
    s = app.session(blob, kind="http")
    keys.append(s.key)
    conn = connect(s.url)
    status, body = get(s.url, s.key, conn=conn)
    assert status == 200, body
    bodies.append(body)
    s.extend()
    status, body = get(s.url, s.key, conn=conn)
    assert status == 200, body
    bodies.append(body)
    url, key = s.url, s.key
    s.close()
    assert get(url, key, conn=conn)[0] != 200, "closing ends the live connection"
    assert get(url, key)[0] != 200, "and refuses new ones"

    # The upstream got the real key every time; the app never saw it.
    seen = world.upstream_seen()
    assert len(seen) == 2, seen
    assert all(r["authorization"] == f"Bearer {SECRET}" and r["path"] == "/v1/models" for r in seen), seen
    assert not any(SECRET in v for v in keys + bodies), "the app never sees the secret"
    assert all('"authorization":"*' in b for b in bodies), f"the upstream's echo is scrubbed: {bodies}"


def test_a_database_password_is_used_through_the_tunnel(world: World) -> None:
    destination = world.start_postgres()
    blob = world.seal_with_cli(PG_PASSWORD, destination)
    app = world.client()
    with app.session(blob, kind="database") as s:
        assert PG_PASSWORD not in s.dsn
        with psycopg.connect(s.dsn, gssencmode="disable") as db:
            assert db.execute("select current_user, 41 + 1").fetchall() == [("app", 42)]


def test_a_redis_password_is_used_through_the_tunnel(world: World) -> None:
    destination = world.start_redis()
    blob = world.seal_with_cli(REDIS_PASSWORD, destination)
    app = world.client()
    with app.session(blob, kind="database") as s:
        assert REDIS_PASSWORD not in s.dsn
        db = redis.Redis.from_url(s.dsn)
        assert db.set("greeting", "hello") is True
        assert db.get("greeting") == b"hello"
        # Commands that leave the sealed database are refused; the connection stays usable.
        with pytest.raises(redis.ResponseError, match="beyond the destination.s database"):
            db.execute_command("SELECT", "1")
        assert db.ping() is True
        db.close()
