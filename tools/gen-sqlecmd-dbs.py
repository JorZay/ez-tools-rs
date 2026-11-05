#!/usr/bin/env python3
"""Makes SQLite databases that SQLECmd's maps run on, since upstream only ships databases for its own TestFiles maps.

    tools/gen-sqlecmd-dbs.py <maps folder> <output folder>
    tools/gen-sqlecmd-dbs.py --fill <database>...    (adds rows to copies of real, empty databases)

For each map, two databases: one with columns of no declared type, one with the declared types in turn. It starts from what
IdentifyQuery names and adds each table and column SQLite reports missing until the map's queries prepare. Rows are the same in
all tables, so joins find them: small integers, reals, text, dates and blobs. The schemas are partly guessed, so this shows
that every query runs and gives the same output on both sides, not that real data looks like this.
"""
import os
import re
import sqlite3
import sys

import yaml

TYPES = ["INTEGER", "TEXT", "REAL", "BLOB", "VARCHAR(255)", "INT", "BIGINT", "LONGVARCHAR", "NUMERIC", "TINYINT", "BOOLEAN", "DATETIME", "FLOAT", "GUID"]
ROWS = [1, 2, 3, 1.5, -1, "text value", "2024-01-02 03:04:05", "13350000000000000", 1700000000, 637000000000000000, None, b"\x01\x02blob", "", '{"a":1,"displayText":"x","b":[1,2]}', "a,b\"c"]


def table_names(sql):
    """Names after FROM and JOIN, with their aliases"""
    found = {}
    for m in re.finditer(r'\b(?:FROM|JOIN)\s+(?!SELECT\b|\()["\[`]?([A-Za-z_][\w$.]*)["\]`]?(?:\s+(?:AS\s+)?([A-Za-z_]\w*))?', sql, re.I):
        name, alias = m.group(1), m.group(2)
        if name.lower().startswith("pragma_") or name.lower() in ("sqlite_master", "json_each", "json_tree"):
            continue
        found[name] = None
        if alias and alias.upper() not in ("ON", "WHERE", "LEFT", "RIGHT", "INNER", "OUTER", "JOIN", "GROUP", "ORDER", "LIMIT", "CROSS", "UNION", "SELECT", "AND", "NATURAL", "USING", "HAVING", "AS"):
            found[alias] = name
    return found


class Db:
    def __init__(self, path, typed):
        self.db = sqlite3.connect(path)
        self.typed = typed
        self.columns = {}
        self.turn = 0

    def next_type(self):
        self.turn += 1
        return TYPES[self.turn % len(TYPES)] if self.typed else ""

    def add_table(self, name):
        if name.lower() in (t.lower() for t in self.columns):
            return False
        if name.lower().startswith("sqlite_"):
            # SQLite's own: an AUTOINCREMENT table makes sqlite_sequence
            self.db.execute('CREATE TABLE IF NOT EXISTS generated_autoincrement (id INTEGER PRIMARY KEY AUTOINCREMENT)')
            return True
        self.db.execute(f'CREATE TABLE "{name}" (dummy_id INTEGER)')
        self.columns[name] = ["dummy_id"]
        return True

    def add_column(self, table, column):
        table = next((t for t in self.columns if t.lower() == table.lower()), table)
        if column.lower() in (c.lower() for c in self.columns.get(table, [])):
            return False
        self.db.execute(f'ALTER TABLE "{table}" ADD COLUMN "{column}" {self.next_type()}')
        self.columns[table].append(column)
        return True

    def fill(self):
        for table, columns in self.columns.items():
            self.db.execute(f'DELETE FROM "{table}"')
            for row, value in enumerate(ROWS):
                names = ",".join(f'"{c}"' for c in columns)
                marks = ",".join("?" for _ in columns)
                self.db.execute(f'INSERT INTO "{table}" ({names}) VALUES ({marks})', [row + 1 if c == "dummy_id" else value for c in columns])
        self.db.commit()


def fix(db, sql):
    """Adds what the query misses, until it prepares or nothing more can be done. True when it prepares"""
    aliases = table_names(sql)
    for _ in range(400):
        try:
            db.db.execute("EXPLAIN " + sql)
            return True
        except sqlite3.Error as e:
            message = str(e)
        m = re.match(r"no such table: (?:main\.)?(.+)", message)
        if m:
            db.add_table(m.group(1))
            continue
        m = re.match(r"(?:no such column|ambiguous column name): (.+)", message)
        if m:
            column = m.group(1).strip('"')
            if "." in column:
                alias, name = column.rsplit(".", 1)
                table = aliases.get(alias) or alias
                if aliases.get(alias, alias) is None:
                    table = alias
                if table not in db.columns:
                    db.add_table(table)
                if db.add_column(table, name):
                    continue
            else:
                # the first table of the query that doesn't have it
                done = False
                for name, target in aliases.items():
                    table = target or name
                    if target is None and table in db.columns and db.add_column(table, column):
                        done = True
                        break
                if done:
                    continue
        return False
    return False


def from_identify(db, query):
    """Tables and columns the identify query counts"""
    for m in re.finditer(r"pragma_table_info\('([^']+)'\)[^)]*?name\s*(?:=\s*'([^']+)'|IN\s*\(([^)]*)\))", query, re.I):
        table = m.group(1)
        db.add_table(table)
        for column in [m.group(2)] if m.group(2) else re.findall(r"'([^']+)'", m.group(3)):
            db.add_column(table, column)
    for m in re.finditer(r"\bname\s*=\s*'([^']+)'", query, re.I):
        if "pragma_table_info" not in query[max(0, m.start() - 80) : m.start()]:
            db.add_table(m.group(1))
    for m in re.finditer(r"\bname\s+IN\s*\(([^)]*)\)", query, re.I):
        if "pragma_table_info" not in query[max(0, m.start() - 80) : m.start()]:
            for name in re.findall(r"'([^']+)'", m.group(1)):
                db.add_table(name)


def fill_existing(path):
    """Adds the same rows to every table of a real database, for its real declared types"""
    db = sqlite3.connect(path)
    db.execute("PRAGMA foreign_keys=OFF")
    tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
    for table in tables:
        try:
            columns = [r[1] for r in db.execute(f'PRAGMA table_info("{table}")')]
            names = ",".join(f'"{c}"' for c in columns)
            marks = ",".join("?" for _ in columns)
            for value in ROWS:
                try:
                    db.execute(f'INSERT OR IGNORE INTO "{table}" ({names}) VALUES ({marks})', [value] * len(columns))
                except sqlite3.Error:
                    pass
        except sqlite3.Error:
            pass
    db.commit()
    db.close()


def main():
    if sys.argv[1] == "--fill":
        for path in sys.argv[2:]:
            fill_existing(path)
        return
    maps, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    total = prepared = identified = 0
    for name in sorted(os.listdir(maps)):
        if not name.endswith(".smap"):
            continue
        with open(os.path.join(maps, name), encoding="utf-8-sig") as f:
            source = yaml.safe_load(f)
        for typed in (False, True):
            folder = os.path.join(out, name[:-5], "typed" if typed else "untyped")
            os.makedirs(folder, exist_ok=True)
            file_name = source["FileName"].replace("*", "x").replace("?", "x")
            path = os.path.join(folder, file_name)
            if os.path.exists(path):
                os.remove(path)
            db = Db(path, typed)
            from_identify(db, source["IdentifyQuery"])
            for query in source["Queries"]:
                ok = fix(db, query["Query"])
                if not typed:
                    total += 1
                    prepared += ok
                    if not ok:
                        print(f"not prepared: {name} {query['BaseFileName']}")
            fix(db, source["IdentifyQuery"])
            db.fill()
            try:
                value = db.db.execute(source["IdentifyQuery"]).fetchone()
                if not typed:
                    same = value is not None and str(value[0]).lower() == str(source["IdentifyValue"]).lower()
                    identified += same
                    if not same:
                        print(f"not identified: {name}: {value} is not {source['IdentifyValue']}")
            except sqlite3.Error as e:
                print(f"identify failed: {name}: {e}")
            db.db.close()
    print(f"queries that prepare: {prepared} of {total}; maps identified: {identified}")


if __name__ == "__main__":
    main()
