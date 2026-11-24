"""Create the design database from schema.sql and run every query from queries.sql.

Python 3.10+, standard library only (useful on Windows where sqlite3 CLI is absent).
Usage:  python db/run_demo.py [path/to/itmon_design.db]
"""
import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def split_statements(sql: str):
    lines = [ln for ln in sql.splitlines() if not ln.lstrip().startswith(".")]  # drop sqlite3 CLI dot-commands
    buf = []
    for line in lines:
        buf.append(line)
        if sqlite3.complete_statement("\n".join(buf)):
            stmt = "\n".join(buf).strip()
            buf = []
            if stmt.strip(";").strip():
                yield stmt


def title_of(stmt: str) -> str:
    comments = [ln.strip("- ").strip() for ln in stmt.splitlines() if ln.strip().startswith("--")]
    numbered = [c for c in comments if c[:1] == "Q" or c[:2] in ("3a", "3b")]
    return (numbered or comments or stmt.splitlines())[-1 if numbered else 0]


def print_table(cur):
    cols = [d[0] for d in cur.description]
    rows = [["" if v is None else str(v) for v in r] for r in cur.fetchall()]
    widths = [max([len(c)] + [len(r[i]) for r in rows]) for i, c in enumerate(cols)]
    print("  ".join(c.ljust(w) for c, w in zip(cols, widths)))
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print("  ".join(v.ljust(w) for v, w in zip(r, widths)))
    print(f"({len(rows)} rows)\n")


def main():
    db_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "itmon_design.db")
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA foreign_keys = ON")
    with open(os.path.join(HERE, "schema.sql"), encoding="utf-8") as f:
        con.executescript(f.read())
    tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    print(f"Database: {db_path}\nTables ({len(tables)}):")
    for t in tables:
        print(f"  {t:<15} {con.execute(f'SELECT COUNT(*) FROM {t}').fetchone()[0]} rows")
    print()
    with open(os.path.join(HERE, "queries.sql"), encoding="utf-8") as f:
        for stmt in split_statements(f.read()):
            print("== " + title_of(stmt))
            cur = con.execute(stmt)
            if cur.description:
                print_table(cur)
            else:
                print(f"rows affected: {cur.rowcount}\n")
    con.commit()
    bad = con.execute("PRAGMA foreign_key_check").fetchall()
    print("foreign_key_check:", "OK" if not bad else bad)
    con.close()


if __name__ == "__main__":
    main()
