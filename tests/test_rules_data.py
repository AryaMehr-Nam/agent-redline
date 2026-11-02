"""Unit tests for destructive data, database, and migration rules."""

from agent_redline.engine import Engine
from agent_redline.models import Decision, RiskLevel, ToolCall, ToolKind


def test_sql_drop_database():
    engine = Engine()
    tc = ToolCall(kind=ToolKind.SHELL, command="psql -U postgres -c 'DROP DATABASE production;'")
    v = engine.evaluate(tc)
    assert v.decision == Decision.DENY
    assert v.risk_level == RiskLevel.CRITICAL
    assert "data.destructive" in v.rule_id


def test_sql_unbounded_delete():
    engine = Engine()
    tc = ToolCall(kind=ToolKind.SHELL, command='sqlite3 app.db "DELETE FROM users;"')
    v = engine.evaluate(tc)
    assert v.decision == Decision.DENY
    assert "where" in v.suggested_alternative.lower()


def test_sql_bounded_delete_allowed():
    engine = Engine()
    tc = ToolCall(kind=ToolKind.SHELL, command='sqlite3 app.db "DELETE FROM users WHERE id = 10;"')
    v = engine.evaluate(tc)
    assert v.decision == Decision.ALLOW


def test_prisma_migrate_reset():
    engine = Engine()  # Balanced mode asks
    tc = ToolCall(kind=ToolKind.SHELL, command="npx prisma migrate reset --force")
    v = engine.evaluate(tc)
    assert v.decision == Decision.ASK
    assert "prisma migrate dev" in v.suggested_alternative.lower()


def test_artisan_migrate_fresh():
    engine = Engine()
    tc = ToolCall(kind=ToolKind.SHELL, command="php artisan migrate:fresh --seed")
    v = engine.evaluate(tc)
    assert v.decision == Decision.ASK
    assert "php artisan migrate" in v.suggested_alternative.lower()


def test_artisan_db_wipe():
    engine = Engine()
    tc = ToolCall(kind=ToolKind.SHELL, command="./artisan db:wipe")
    v = engine.evaluate(tc)
    assert v.decision == Decision.ASK


def test_benign_migrations():
    engine = Engine()
    benign = [
        "php artisan migrate",
        "php artisan migrate:status",
        "npx prisma migrate dev",
        "npx prisma db push",
        "psql -c 'SELECT count(*) FROM users;'",
    ]
    for cmd in benign:
        tc = ToolCall(kind=ToolKind.SHELL, command=cmd)
        v = engine.evaluate(tc)
        assert v.decision == Decision.ALLOW, f"Expected {cmd} to be allowed"
