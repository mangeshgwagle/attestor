#!/usr/bin/env python3
"""Sales analysis engine -- ingest, clean, trend, anomaly, forecast.

    from sales_engine import SalesAnalyzer
    sa = SalesAnalyzer("data/sales/")
    sa.ingest("shopify_export.csv")
    report = sa.analyze()
    print(sa.render(report))
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import re
import sqlite3
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path


DB_NAME = "sales.db"

COLUMN_ALIASES = {
    "date": ["date", "order_date", "created_at", "transaction_date",
             "sale_date", "invoice_date", "order date", "txn date"],
    "amount": ["amount", "total", "gross_sales", "net_amount", "revenue",
               "sale_amount", "order_total", "total_price", "subtotal",
               "net sales", "gross sales"],
    "quantity": ["quantity", "qty", "units", "items_sold", "units_sold",
                 "line_quantity", "quantity ordered"],
    "product": ["product", "item", "product_name", "sku", "item_name",
                "description", "product_title", "line_item"],
    "category": ["category", "type", "product_type", "department",
                 "product_category", "group"],
    "customer": ["customer", "customer_name", "buyer", "client",
                 "bill_to", "sold_to"],
    "order_id": ["order_id", "order_number", "invoice", "transaction_id",
                 "ref", "reference", "order"],
}


@dataclass
class SalesRecord:
    date: str
    amount: float
    quantity: int = 1
    product: str = ""
    category: str = ""
    customer: str = ""
    order_id: str = ""
    source: str = ""


@dataclass
class TrendPoint:
    period: str
    revenue: float
    units: int
    orders: int
    avg_order: float
    wow_change: float | None = None


@dataclass
class Anomaly:
    period: str
    metric: str
    value: float
    expected: float
    deviation: float
    direction: str


@dataclass
class Forecast:
    period: str
    predicted_revenue: float
    lower_bound: float
    upper_bound: float
    confidence: float


@dataclass
class SalesReport:
    period_start: str
    period_end: str
    total_revenue: float
    total_units: int
    total_orders: int
    avg_order_value: float
    top_products: list[dict]
    top_categories: list[dict]
    weekly_trends: list[TrendPoint]
    anomalies: list[Anomaly]
    forecasts: list[Forecast]
    daily_breakdown: list[dict]


class SalesAnalyzer:
    def __init__(self, data_dir: str = "."):
        self.data_dir = Path(data_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.data_dir / DB_NAME
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sales (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                amount REAL NOT NULL,
                quantity INTEGER DEFAULT 1,
                product TEXT DEFAULT '',
                category TEXT DEFAULT '',
                customer TEXT DEFAULT '',
                order_id TEXT DEFAULT '',
                source TEXT DEFAULT '',
                file_hash TEXT DEFAULT '',
                imported_at TEXT DEFAULT ''
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS import_log (
                file_hash TEXT PRIMARY KEY,
                filename TEXT,
                rows_imported INTEGER,
                imported_at TEXT
            )
        """)
        conn.commit()
        conn.close()

    def ingest(self, csv_path: str, source: str = "") -> dict:
        path = Path(csv_path)
        if not path.exists():
            raise FileNotFoundError(f"CSV not found: {csv_path}")

        file_hash = hashlib.md5(path.read_bytes()).hexdigest()

        conn = sqlite3.connect(str(self.db_path))
        existing = conn.execute(
            "SELECT 1 FROM import_log WHERE file_hash = ?",
            (file_hash,)).fetchone()
        if existing:
            conn.close()
            return {"status": "skipped", "reason": "already imported",
                    "file": str(path)}

        rows = self._parse_csv(path, source or path.stem, file_hash)
        if not rows:
            conn.close()
            return {"status": "error", "reason": "no valid rows found"}

        conn.executemany(
            "INSERT INTO sales (date, amount, quantity, product, category, "
            "customer, order_id, source, file_hash, imported_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(r.date, r.amount, r.quantity, r.product, r.category,
              r.customer, r.order_id, r.source, file_hash,
              datetime.now(timezone.utc).isoformat())
             for r in rows]
        )
        conn.execute(
            "INSERT INTO import_log (file_hash, filename, rows_imported, imported_at) "
            "VALUES (?, ?, ?, ?)",
            (file_hash, path.name, len(rows),
             datetime.now(timezone.utc).isoformat())
        )
        conn.commit()
        conn.close()

        return {"status": "imported", "rows": len(rows), "file": str(path)}

    def _parse_csv(self, path: Path, source: str,
                   file_hash: str) -> list[SalesRecord]:
        with open(path, encoding="utf-8-sig", errors="replace") as f:
            sample = f.read(4096)
            f.seek(0)
            dialect = csv.Sniffer().sniff(sample) if sample.strip() else None
            reader = csv.DictReader(f, dialect=dialect)
            if not reader.fieldnames:
                return []

            col_map = self._map_columns(reader.fieldnames)
            records = []
            for row in reader:
                try:
                    rec = self._row_to_record(row, col_map, source)
                    if rec:
                        records.append(rec)
                except (ValueError, KeyError):
                    continue
            return records

    def _map_columns(self, headers: list[str]) -> dict[str, str]:
        mapping = {}
        normalized = {h: h.strip().lower().replace(" ", "_") for h in headers}
        for field_name, aliases in COLUMN_ALIASES.items():
            for header, norm in normalized.items():
                if norm in aliases:
                    mapping[field_name] = header
                    break
        return mapping

    def _row_to_record(self, row: dict, col_map: dict,
                       source: str) -> SalesRecord | None:
        date_col = col_map.get("date")
        amount_col = col_map.get("amount")
        if not date_col or not amount_col:
            return None

        date_raw = row.get(date_col, "").strip()
        amount_raw = row.get(amount_col, "").strip()
        if not date_raw or not amount_raw:
            return None

        date_str = self._parse_date(date_raw)
        if not date_str:
            return None

        amount = self._parse_amount(amount_raw)
        if amount is None:
            return None

        qty_col = col_map.get("quantity")
        quantity = int(float(row.get(qty_col, "1") or "1")) if qty_col else 1

        return SalesRecord(
            date=date_str,
            amount=amount,
            quantity=max(quantity, 1),
            product=row.get(col_map.get("product", ""), "").strip(),
            category=row.get(col_map.get("category", ""), "").strip(),
            customer=row.get(col_map.get("customer", ""), "").strip(),
            order_id=row.get(col_map.get("order_id", ""), "").strip(),
            source=source,
        )

    def _parse_date(self, raw: str) -> str | None:
        formats = [
            "%Y-%m-%d", "%m/%d/%Y", "%d/%m/%Y", "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S", "%m/%d/%y", "%d-%m-%Y", "%b %d, %Y",
            "%B %d, %Y", "%Y%m%d",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(raw[:19], fmt)
                return dt.strftime("%Y-%m-%d")
            except ValueError:
                continue
        return None

    def _parse_amount(self, raw: str) -> float | None:
        cleaned = re.sub(r'[^\d.\-]', '', raw.replace(",", ""))
        try:
            return float(cleaned)
        except ValueError:
            return None

    def _query(self, sql: str, params: tuple = ()) -> list[dict]:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
        conn.close()
        return rows

    def analyze(self, days: int = 90) -> SalesReport:
        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")

        daily = self._query(
            "SELECT date, SUM(amount) as revenue, SUM(quantity) as units, "
            "COUNT(DISTINCT order_id) as orders FROM sales "
            "WHERE date >= ? GROUP BY date ORDER BY date", (cutoff,))

        if not daily:
            return SalesReport(
                period_start=cutoff,
                period_end=datetime.now().strftime("%Y-%m-%d"),
                total_revenue=0, total_units=0, total_orders=0,
                avg_order_value=0, top_products=[], top_categories=[],
                weekly_trends=[], anomalies=[], forecasts=[],
                daily_breakdown=[])

        total_rev = sum(d["revenue"] for d in daily)
        total_units = sum(d["units"] for d in daily)
        total_orders = sum(d["orders"] for d in daily)
        avg_order = total_rev / max(total_orders, 1)

        top_products = self._query(
            "SELECT product, SUM(amount) as revenue, SUM(quantity) as units "
            "FROM sales WHERE date >= ? AND product != '' "
            "GROUP BY product ORDER BY revenue DESC LIMIT 10", (cutoff,))

        top_categories = self._query(
            "SELECT category, SUM(amount) as revenue, SUM(quantity) as units "
            "FROM sales WHERE date >= ? AND category != '' "
            "GROUP BY category ORDER BY revenue DESC LIMIT 10", (cutoff,))

        weekly = self._weekly_trends(daily)
        anomalies = self._detect_anomalies(daily)
        forecasts = self._forecast(daily)

        return SalesReport(
            period_start=daily[0]["date"],
            period_end=daily[-1]["date"],
            total_revenue=round(total_rev, 2),
            total_units=total_units,
            total_orders=total_orders,
            avg_order_value=round(avg_order, 2),
            top_products=top_products,
            top_categories=top_categories,
            weekly_trends=weekly,
            anomalies=anomalies,
            forecasts=forecasts,
            daily_breakdown=daily,
        )

    def _weekly_trends(self, daily: list[dict]) -> list[TrendPoint]:
        weeks: dict[str, dict] = defaultdict(
            lambda: {"revenue": 0, "units": 0, "orders": 0})

        for d in daily:
            dt = datetime.strptime(d["date"], "%Y-%m-%d")
            week_start = (dt - timedelta(days=dt.weekday())).strftime("%Y-%m-%d")
            weeks[week_start]["revenue"] += d["revenue"]
            weeks[week_start]["units"] += d["units"]
            weeks[week_start]["orders"] += d["orders"]

        sorted_weeks = sorted(weeks.items())
        trends = []
        for i, (period, data) in enumerate(sorted_weeks):
            orders = max(data["orders"], 1)
            wow = None
            if i > 0:
                prev_rev = sorted_weeks[i - 1][1]["revenue"]
                if prev_rev > 0:
                    wow = round((data["revenue"] - prev_rev) / prev_rev * 100, 1)
            trends.append(TrendPoint(
                period=period,
                revenue=round(data["revenue"], 2),
                units=data["units"],
                orders=data["orders"],
                avg_order=round(data["revenue"] / orders, 2),
                wow_change=wow,
            ))
        return trends

    def _detect_anomalies(self, daily: list[dict],
                          z_threshold: float = 2.0) -> list[Anomaly]:
        if len(daily) < 7:
            return []

        revenues = [d["revenue"] for d in daily]
        mean_rev = statistics.mean(revenues)
        stdev_rev = statistics.stdev(revenues) if len(revenues) > 1 else 0

        anomalies = []
        if stdev_rev > 0:
            for d in daily:
                z = (d["revenue"] - mean_rev) / stdev_rev
                if abs(z) >= z_threshold:
                    anomalies.append(Anomaly(
                        period=d["date"],
                        metric="daily_revenue",
                        value=round(d["revenue"], 2),
                        expected=round(mean_rev, 2),
                        deviation=round(z, 2),
                        direction="spike" if z > 0 else "drop",
                    ))

        window = 7
        for i in range(window, len(daily)):
            window_revs = [daily[j]["revenue"] for j in range(i - window, i)]
            w_mean = statistics.mean(window_revs)
            w_std = statistics.stdev(window_revs) if len(window_revs) > 1 else 0
            if w_std > 0:
                z = (daily[i]["revenue"] - w_mean) / w_std
                if abs(z) >= z_threshold and not any(
                        a.period == daily[i]["date"] for a in anomalies):
                    anomalies.append(Anomaly(
                        period=daily[i]["date"],
                        metric="rolling_7d_revenue",
                        value=round(daily[i]["revenue"], 2),
                        expected=round(w_mean, 2),
                        deviation=round(z, 2),
                        direction="spike" if z > 0 else "drop",
                    ))

        return sorted(anomalies, key=lambda a: abs(a.deviation), reverse=True)

    def _forecast(self, daily: list[dict],
                  horizon: int = 7) -> list[Forecast]:
        if len(daily) < 14:
            return []

        revenues = [d["revenue"] for d in daily]
        n = len(revenues)

        x_mean = (n - 1) / 2
        y_mean = statistics.mean(revenues)

        numerator = sum((i - x_mean) * (revenues[i] - y_mean) for i in range(n))
        denominator = sum((i - x_mean) ** 2 for i in range(n))
        slope = numerator / denominator if denominator else 0
        intercept = y_mean - slope * x_mean

        residuals = [revenues[i] - (slope * i + intercept) for i in range(n)]
        std_err = statistics.stdev(residuals) if len(residuals) > 1 else 0

        last_date = datetime.strptime(daily[-1]["date"], "%Y-%m-%d")
        forecasts = []
        for day in range(1, horizon + 1):
            x = n + day - 1
            predicted = slope * x + intercept
            predicted = max(predicted, 0)

            margin = std_err * 1.96 * math.sqrt(1 + 1/n + (x - x_mean)**2 / max(denominator, 1))
            forecast_date = (last_date + timedelta(days=day)).strftime("%Y-%m-%d")

            forecasts.append(Forecast(
                period=forecast_date,
                predicted_revenue=round(predicted, 2),
                lower_bound=round(max(predicted - margin, 0), 2),
                upper_bound=round(predicted + margin, 2),
                confidence=0.95,
            ))
        return forecasts

    def get_record_count(self) -> int:
        rows = self._query("SELECT COUNT(*) as cnt FROM sales")
        return rows[0]["cnt"] if rows else 0

    def clear(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("DELETE FROM sales")
        conn.execute("DELETE FROM import_log")
        conn.commit()
        conn.close()

    def render(self, report: SalesReport) -> str:
        lines = [
            "\n  Sales Analysis Report",
            "  " + "=" * 55,
            f"  Period: {report.period_start} to {report.period_end}",
            f"  Revenue:    ${report.total_revenue:,.2f}",
            f"  Units sold: {report.total_units:,}",
            f"  Orders:     {report.total_orders:,}",
            f"  Avg order:  ${report.avg_order_value:,.2f}",
        ]

        if report.top_products:
            lines.append(f"\n  Top Products:")
            for p in report.top_products[:5]:
                lines.append(f"    ${p['revenue']:>10,.2f}  {p['units']:>5d} units  "
                             f"{p['product']}")

        if report.weekly_trends:
            lines.append(f"\n  Weekly Trends:")
            for t in report.weekly_trends[-8:]:
                wow = f" ({t.wow_change:+.1f}%)" if t.wow_change is not None else ""
                lines.append(f"    {t.period}  ${t.revenue:>10,.2f}  "
                             f"{t.units:>5d} units{wow}")

        if report.anomalies:
            lines.append(f"\n  Anomalies Detected:")
            for a in report.anomalies[:5]:
                lines.append(f"    {a.direction.upper():5s}  {a.period}  "
                             f"${a.value:,.2f} (expected ${a.expected:,.2f}, "
                             f"{a.deviation:+.1f}σ)")

        if report.forecasts:
            lines.append(f"\n  7-Day Forecast:")
            for f in report.forecasts:
                lines.append(f"    {f.period}  ${f.predicted_revenue:>10,.2f}  "
                             f"(${f.lower_bound:,.2f} - ${f.upper_bound:,.2f})")

        lines.append("  " + "=" * 55)
        return "\n".join(lines)


def to_dict(report: SalesReport) -> dict:
    return {
        "period": {"start": report.period_start, "end": report.period_end},
        "summary": {
            "revenue": report.total_revenue,
            "units": report.total_units,
            "orders": report.total_orders,
            "avg_order_value": report.avg_order_value,
        },
        "top_products": report.top_products,
        "top_categories": report.top_categories,
        "weekly_trends": [
            {"period": t.period, "revenue": t.revenue, "units": t.units,
             "orders": t.orders, "avg_order": t.avg_order,
             "wow_change": t.wow_change}
            for t in report.weekly_trends
        ],
        "anomalies": [
            {"period": a.period, "metric": a.metric, "value": a.value,
             "expected": a.expected, "deviation": a.deviation,
             "direction": a.direction}
            for a in report.anomalies
        ],
        "forecasts": [
            {"period": f.period, "predicted": f.predicted_revenue,
             "lower": f.lower_bound, "upper": f.upper_bound,
             "confidence": f.confidence}
            for f in report.forecasts
        ],
        "daily": report.daily_breakdown,
    }
