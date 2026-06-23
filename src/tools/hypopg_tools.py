"""Core HypoPG logic for virtual index analysis on EDBAS 9.6.

All async functions in this module operate on an already-acquired asyncpg
connection. They are designed to be importable and callable from any tool
registration module (pg_tools.py) or directly by other MCP tools, ensuring
reusability across the codebase.
"""

from __future__ import annotations

import itertools
import logging
import re
from typing import Any

from fastmcp.exceptions import ToolError

logger = logging.getLogger(__name__)

# Regex patterns for SQL parsing (EDBAS 9.6 compatible)
_RE_FROM_TABLE = re.compile(
    r"""
    (?:FROM|JOIN)\s+
    (?:ONLY\s+)?
    (?:"?(\w+)"?\."?(\w+)"?|\b(\w+))\b
    (?:\s+(?:AS\s+)?(\w+))?
    """,
    re.IGNORECASE | re.VERBOSE,
)

_RE_WHERE_COL = re.compile(
    r"""
    (?:"?(\w+)"?\."?(\w+)"?|\b(\w+))\.(\w+)
    \s*(?:>=|<=|!=|<>|=|<|>|IS|IN|LIKE|BETWEEN)
    """,
    re.IGNORECASE | re.VERBOSE,
)

_RE_JOIN_ON_COL = re.compile(
    r"""
    ON\s+
    (?:"?(\w+)"?\."?(\w+)"?|\b(\w+))\.(\w+)
    \s*=\s*
    (?:"?(\w+)"?\."?(\w+)"?|\b(\w+))\.(\w+)
    """,
    re.IGNORECASE | re.VERBOSE,
)

_RE_ORDER_BY_COL = re.compile(
    r"""
    ORDER\s+BY\s+
    (?:"?(\w+)"?\."?(\w+)"?|\b(\w+))\.(\w+)
    """,
    re.IGNORECASE | re.VERBOSE,
)


async def parse_tables_and_columns(
    conn: Any, query_text: str
) -> dict[str, Any]:
    """Parse SQL text to extract referenced tables and columns.

    Uses regex to identify tables/columns in FROM, JOIN, WHERE,
    ORDER BY, and GROUP BY clauses. Validates against
    information_schema.columns for the connected database.

    Args:
        conn: An active asyncpg connection.
        query_text: The SQL SELECT statement to analyze.

    Returns:
        A dict with:
            - "tables": dict mapping table_name -> {columns, flags}
            - "column_refs": list of (schema, table, column) tuples found
    """
    tables_found: dict[str, set[str]] = {}
    column_refs_raw: list[tuple[str | None, str, str]] = []
    aliases: dict[str, str] = {}

    # --- Pass 1: Extract FROM/JOIN table references and aliases ---
    for match in _RE_FROM_TABLE.finditer(query_text):
        schema_table = match.group(1)
        table_name = match.group(2) or match.group(3)
        alias = match.group(4)
        if table_name:
            qualified = f"{schema_table}.{table_name}" if schema_table else table_name
            if qualified not in tables_found:
                tables_found[qualified] = set()
            if alias:
                aliases[alias] = qualified

    # --- Pass 2: Extract WHERE column references ---
    for match in _RE_WHERE_COL.finditer(query_text):
        schema_or_alias = match.group(1) or match.group(3)
        col = match.group(2) or match.group(4)
        if schema_or_alias and col:
            resolved = aliases.get(schema_or_alias, schema_or_alias)
            column_refs_raw.append((None, resolved, col))

    # --- Pass 3: Extract JOIN ON column references ---
    for match in _RE_JOIN_ON_COL.finditer(query_text):
        for side in (1, 5):
            schema_or_alias = match.group(side) or match.group(side + 2)
            col = match.group(side + 1) or match.group(side + 3)
            if schema_or_alias and col:
                resolved = aliases.get(schema_or_alias, schema_or_alias)
                column_refs_raw.append((None, resolved, col))

    # --- Pass 4: Extract ORDER BY column references ---
    for match in _RE_ORDER_BY_COL.finditer(query_text):
        schema_or_alias = match.group(1) or match.group(3)
        col = match.group(2) or match.group(4)
        if schema_or_alias and col:
            resolved = aliases.get(schema_or_alias, schema_or_alias)
            column_refs_raw.append((None, resolved, col))

    # --- Pass 5: Validate columns against information_schema ---
    validated_columns: dict[str, list[str]] = {}
    for _, table_ref, col in column_refs_raw:
        if table_ref not in tables_found:
            # Could be a table we didn't catch via FROM/JOIN parsing
            tables_found[table_ref] = set()
        tables_found[table_ref].add(col)

    # Verify columns exist via information_schema (best-effort)
    for table_name in list(tables_found.keys()):
        try:
            schema_part = "public"
            table_part = table_name
            if "." in table_name:
                schema_part, table_part = table_name.split(".", 1)
            rows = await conn.fetch(
                """
                SELECT column_name, data_type
                FROM information_schema.columns
                WHERE table_schema = $1 AND table_name = $2
                """,
                schema_part,
                table_part,
            )
            valid_cols = {r["column_name"] for r in rows}
            # Keep only columns that actually exist
            tables_found[table_name] = {c for c in tables_found[table_name] if c in valid_cols}
            validated_columns[table_name] = [r["column_name"] for r in rows]
        except Exception:
            logger.warning("Could not validate columns for table %s", table_name, exc_info=True)
            validated_columns[table_name] = list(tables_found[table_name])

    # Build result
    result_tables: dict[str, dict[str, Any]] = {}
    for table_name, cols in tables_found.items():
        if not cols:
            cols = validated_columns.get(table_name, set())  # type: ignore[arg-type]
        result_tables[table_name] = {
            "referenced_columns": list(cols),
            "all_columns": validated_columns.get(table_name, []),
        }

    return {
        "tables": result_tables,
        "column_refs": column_refs_raw,
    }


async def hypopg_create_virtual_indexes(
    conn: Any,
    query_analysis: dict[str, Any],
) -> list[dict[str, Any]]:
    """Generate and create candidate virtual indexes using HypoPG.

    Creates single-column B-tree indexes on columns referenced in
    WHERE/JOIN/ORDER BY clauses. Each index is created as a virtual
    index via hypopg_create_index().

    Args:
        conn: An active asyncpg connection (must have hypopg loaded).
        query_analysis: Output from parse_tables_and_columns().

    Returns:
        List of dicts with {"index_name", "oid", "indexdef"} for
        each created virtual index. Empty list if no candidates.
    """
    created: list[dict[str, Any]] = []

    # Defensive reset before creating new virtual indexes
    try:
        await conn.execute("SELECT hypopg_reset()")
    except Exception:
        logger.warning("hypopg_reset() failed (extension may not be loaded)")
        raise ToolError("HypoPG extension is not available on this instance") from None

    tables = query_analysis.get("tables", {})
    for table_name, info in tables.items():
        ref_cols = info.get("referenced_columns", [])
        for col in ref_cols:
            index_def = f"CREATE INDEX ON {table_name} ({col})"
            try:
                row = await conn.fetchrow("SELECT * FROM hypopg_create_index($1)", index_def)
                if row:
                    created.append(
                        {
                            "index_name": f"<virtual>{table_name}_{col}_idx",
                            "oid": row[0] if row else 0,
                            "indexdef": index_def,
                        }
                    )
            except Exception as exc:
                logger.warning("Failed to create virtual index %s: %s", index_def, exc)

    return created


async def hypopg_explain_with_virtual(
    conn: Any,
    query_text: str,
) -> dict[str, Any]:
    """Run EXPLAIN (FORMAT JSON) for a query against the current session.

    The session may have virtual indexes active from prior
    hypopg_create_index() calls.

    Args:
        conn: An active asyncpg connection.
        query_text: The SQL SELECT statement to explain.

    Returns:
        Dict with "plan" (the raw JSON plan) and "total_cost" (float).
    """
    explain_sql = f"EXPLAIN (FORMAT JSON) {query_text}"
    try:
        row = await conn.fetchrow(explain_sql)
    except Exception as exc:
        raise ToolError(f"EXPLAIN failed: {exc}") from exc

    if not row or not row[0]:
        raise ToolError("EXPLAIN returned no plan")

    plan_list = row[0]  # EXPLAIN FORMAT JSON returns a list
    if isinstance(plan_list, list) and len(plan_list) > 0:
        plan = plan_list[0]
    else:
        plan = plan_list

    if isinstance(plan, dict):
        total_cost = float(plan.get("Plan", {}).get("Total Cost", 0))
    else:
        total_cost = 0
    return {"plan": plan, "total_cost": total_cost}


async def hypopg_find_optimal_indexes(
    conn: Any,
    query_text: str,
    max_combinations: int = 10,
) -> dict[str, Any]:
    """Find optimal virtual index combination for a query.

    Orchestrator that:
    1. Captures baseline EXPLAIN cost without virtual indexes.
    2. Parses query and creates candidate virtual indexes.
    3. Generates combinations (singletons, pairwise, triplets).
    4. Tests each combination via EXPLAIN, ranks by cost.
    5. Cleans up virtual indexes at the end.

    Args:
        conn: An active asyncpg connection with hypopg loaded.
        query_text: The SQL SELECT statement to optimize.
        max_combinations: Maximum number of combos to test (default 10).

    Returns:
        Dict with baseline_cost, ranked_plans (top 5+), and
        best_recommendation.
    """
    # Step 1: Baseline cost — init defaults before guarded calls
    baseline: dict[str, Any] = {}
    baseline_cost: float = 0.0
    try:
        await conn.execute("SELECT hypopg_reset()")
    except Exception:
        raise ToolError("HypoPG extension is not available on this instance") from None

    baseline = await hypopg_explain_with_virtual(conn, query_text)
    baseline_cost = baseline["total_cost"]

    # Step 2: Parse query and create candidate indexes
    query_analysis = await parse_tables_and_columns(conn, query_text)
    all_virtual = await hypopg_create_virtual_indexes(conn, query_analysis)

    if not all_virtual:
        # No candidates generated — return baseline only
        return {
            "baseline_cost": baseline_cost,
            "baseline_plan": baseline["plan"],
            "ranked_plans": [
                {
                    "rank": 1,
                    "virtual_indexes_used": [],
                    "total_cost": baseline_cost,
                    "cost_improvement_pct": 0.0,
                    "explain_plan": baseline["plan"],
                    "description": "Baseline plan (no index candidates found)",
                }
            ],
            "best_recommendation": {
                "virtual_indexes": [],
                "total_cost": baseline_cost,
                "improvement_pct": 0.0,
            },
        }

    ranked_plans: list[dict[str, Any]] = []

    try:
        # Step 3: Generate combinations
        indices = list(range(len(all_virtual)))
        combos_tested = 0

        # Determine combination sizes to try
        combo_sizes = []
        remaining = max_combinations
        for size in range(1, len(indices) + 1):
            n_for_size = len(list(itertools.combinations(indices, size)))
            take = min(n_for_size, remaining)
            if take > 0:
                combo_sizes.append((size, take))
                remaining -= take
            if remaining <= 0:
                break

        for size, take_count in combo_sizes:
            for combo_indices in itertools.islice(
                itertools.combinations(indices, size), take_count
            ):
                if combos_tested >= max_combinations:
                    break

                # Reset and create only this combination
                await conn.execute("SELECT hypopg_reset()")
                combo_indexes = []
                for idx in combo_indices:
                    v = all_virtual[idx]
                    await conn.execute("SELECT * FROM hypopg_create_index($1)", v["indexdef"])
                    combo_indexes.append(v)

                # Test this combination
                result = await hypopg_explain_with_virtual(conn, query_text)
                cost = result["total_cost"]
                improvement = (
                    ((baseline_cost - cost) / baseline_cost * 100) if baseline_cost > 0 else 0.0
                )

                ranked_plans.append(
                    {
                        "rank": 0,  # will assign after sorting
                        "virtual_indexes_used": [v["indexdef"] for v in combo_indexes],
                        "total_cost": cost,
                        "cost_improvement_pct": round(improvement, 2),
                        "explain_plan": result["plan"],
                        "description": (f"Plan with {len(combo_indexes)} virtual index(es)"),
                    }
                )
                combos_tested += 1

    finally:
        # Always clean up virtual indexes
        try:
            await conn.execute("SELECT hypopg_reset()")
        except Exception:
            logger.warning("hypopg_reset() cleanup failed", exc_info=True)

    # Also include baseline as a reference point
    ranked_plans.append(
        {
            "rank": 0,
            "virtual_indexes_used": [],
            "total_cost": baseline_cost,
            "cost_improvement_pct": 0.0,
            "explain_plan": baseline["plan"],
            "description": "Baseline (no virtual indexes)",
        }
    )

    # Step 4: Sort by cost ascending and assign ranks
    ranked_plans.sort(key=lambda p: p["total_cost"])
    for i, plan in enumerate(ranked_plans, start=1):
        plan["rank"] = i

    # Take top max_combinations (at least top 5)
    top_plans = ranked_plans[: max(max_combinations, 5)]

    # Best recommendation is the lowest cost plan (excluding baseline if it's the same)
    best = top_plans[0] if top_plans else ranked_plans[0]

    return {
        "baseline_cost": baseline_cost,
        "baseline_plan": baseline["plan"],
        "ranked_plans": top_plans,
        "best_recommendation": {
            "virtual_indexes": best["virtual_indexes_used"],
            "total_cost": best["total_cost"],
            "improvement_pct": best["cost_improvement_pct"],
        },
    }
