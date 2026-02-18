from __future__ import annotations

from typing import Any, Awaitable, Callable
import zmq
import json
import sqlite3
import time

from nodal_sdk.component import Component
from nodal_sdk.types import Mitigation as MT, MitigationType


class Mitigation:
    def __init__(self, mitigator: Mitigator, mitigation: MT):
        self.mitigator = mitigator
        self.mitigation = mitigation
        self.user_data_text = None

    def set_enabled(self):
        self.mitigation["status"] = "Enabled"
        self.mitigation["mitigator"] = self.mitigator.name
        self.mitigator.send("mitigation", self.mitigation)

    def set_disabled(self):
        self.mitigation["status"] = "Disabled"
        self.mitigation["mitigator"] = self.mitigator.name
        self.mitigator.send("mitigation", self.mitigation)

    def get_id(self) -> str:
        return self.mitigation["mitigation_id"]

    def get_status(self) -> str:
        return self.mitigation["status"]

    def get_targets(self) -> MitigationType:
        return self.mitigation["targets"]

    def get_ts(self) -> float:
        return self.mitigation["ts"]

    def get_exp(self) -> float:
        return self.mitigation["expiry"]

    def get_data(self) -> MT:
        return self.mitigation

    def set_user_data(self, user_data):
        self.user_data_text = json.dumps(user_data)

    def set_user_data_text(self, user_data_text):
        self.user_data_text = user_data_text

    def get_user_data(self):
        if self.user_data_text is None:
            return None
        return json.loads(self.user_data_text)

    def get_user_data_text(self):
        return self.user_data_text


class Mitigator(Component):
    db: sqlite3.Connection

    def __init__(self, name: str, port: int):
        self._initdb(name)
        context = zmq.Context.instance()
        super().__init__(name, "Mitigator", port, context)

    def _initdb(self, name: str):
        self.db = sqlite3.connect(f"{name}.mitigator.db")
        c = self.db.cursor()
        c.execute(
            "CREATE TABLE IF NOT EXISTS mitigations (id VARCHAR(50) PRIMARY KEY NOT NULL, ts FLOAT, exp FLOAT, mitigation TEXT, user_data TEXT)"
        )
        self.db.commit()

    def _persist(self, mit: Any):
        if not isinstance(mit, Mitigation):
            raise Exception("Handler must return a mitigation object.")

        if mit.get_status() == "Enabled":
            if mit.get_exp() is None:
                print("(mit sdk) ! received permanent mitigation")

            c = self.db.cursor()
            c.execute(
                """
                INSERT INTO mitigations (id, ts, exp, mitigation, user_data) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT DO UPDATE SET
                ts = EXCLUDED.ts,
                exp = EXCLUDED.exp,
                mitigation = EXCLUDED.mitigation
                """,
                (
                    mit.get_id(),
                    mit.get_ts(),
                    mit.get_exp(),
                    json.dumps(mit.get_data()),
                    mit.get_user_data_text(),
                ),
            )
            self.db.commit()
        elif mit.get_status() == "Disabled":
            c = self.db.cursor()
            c.execute(
                """
                DELETE FROM mitigations WHERE
                id = ?
                """,
                (mit.get_id(),),
            )
            self.db.commit()

    async def _check(self, disable_handler: Callable[[Mitigation], Awaitable[Any]]):
        cur_ts = time.time()
        c = self.db.cursor()
        c.execute(
            "SELECT * FROM mitigations WHERE exp < ? AND exp IS NOT NULL", (cur_ts,)
        )
        expired = c.fetchall()

        for _, _, _, mitigation, user_data in expired:
            m = Mitigation(self, json.loads(mitigation))
            m.set_user_data_text(user_data)
            await disable_handler(m)

        c.execute(
            "DELETE FROM mitigations WHERE exp < ? AND exp IS NOT NULL", (cur_ts,)
        )
        self.db.commit()

    def _fetch_user_data(self, m: Mitigation):
        c = self.db.cursor()
        c.execute("SELECT user_data FROM mitigations WHERE id = ?", (m.get_id(),))
        f = c.fetchall()

        for user_data in f:
            m.set_user_data_text(user_data[0])

    def _dedupe(self, m: Mitigation) -> bool:
        c = self.db.cursor()
        c.execute("SELECT id, exp FROM mitigations WHERE id = ?", (m.get_id(),))
        existing = c.fetchone()
        if existing:
            mitigation_id, exp = existing
            if exp is None or m.get_exp() is None or exp < m.get_exp():
                c.execute(
                    """
                    UPDATE mitigations 
                    SET exp = ?, ts = ?, mitigation = ? 
                    WHERE id = ?
                    """,
                    (m.get_exp(), m.get_ts(), json.dumps(m.get_data()), mitigation_id),
                )
            return False

        return True

    async def handle(
        self,
        enable_handler: Callable[[Mitigation], Awaitable[Any]],
        disable_handler: Callable[[Mitigation], Awaitable[Any]],
        refresh_handler: Callable[[Mitigation], Awaitable[Any]] | None = None,
    ):
        await self._check(disable_handler)

        async for cmd, data in self.recv():
            match cmd:
                case "mitigation":
                    m = Mitigation(self, data)
                    if m.get_status() == "Requested":
                        is_new_mitigation = self._dedupe(m)
                        if is_new_mitigation:
                            result = await enable_handler(m)
                            if result:
                                self._persist(result)
                        elif refresh_handler:
                            result = await refresh_handler(m)
                            if result:
                                self._persist(result)
                    elif m.get_status() == "Unrequested":
                        self._fetch_user_data(m)
                        result = await disable_handler(m)
                        if result:
                            self._persist(result)
                    break
