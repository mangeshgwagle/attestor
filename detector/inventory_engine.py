#!/usr/bin/env python3
"""Inventory monitoring engine -- threshold alerts and PO draft generation.

    from inventory_engine import InventoryMonitor
    mon = InventoryMonitor("data/inventory/")
    mon.load_stock("current_stock.csv")
    mon.set_threshold("Widget A", min_qty=50, reorder_qty=200)
    alerts = mon.check_thresholds()
    mon.generate_po(alerts, vendor="Acme Corp")
"""
from __future__ import annotations

import csv
import json
import os
import smtplib
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.mime.text import MIMEText
from pathlib import Path


@dataclass
class StockItem:
    sku: str
    name: str
    quantity: int
    unit_cost: float = 0.0
    category: str = ""
    vendor: str = ""
    location: str = ""


@dataclass
class Threshold:
    sku: str
    min_qty: int
    reorder_qty: int
    max_qty: int = 0
    auto_po: bool = False


@dataclass
class StockAlert:
    sku: str
    name: str
    current_qty: int
    min_qty: int
    reorder_qty: int
    shortfall: int
    unit_cost: float
    severity: str


@dataclass
class PurchaseOrder:
    po_number: str
    vendor: str
    date: str
    items: list[dict]
    total: float
    status: str = "draft"


STOCK_COLUMN_ALIASES = {
    "sku": ["sku", "item_id", "product_id", "item_code", "code", "id",
            "product_code", "barcode"],
    "name": ["name", "product", "item", "description", "product_name",
             "item_name", "title"],
    "quantity": ["quantity", "qty", "stock", "on_hand", "in_stock",
                 "available", "count", "units"],
    "unit_cost": ["unit_cost", "cost", "price", "unit_price", "cost_price",
                  "wholesale", "buy_price"],
    "category": ["category", "type", "group", "department", "class"],
    "vendor": ["vendor", "supplier", "manufacturer", "brand"],
}


class InventoryMonitor:
    def __init__(self, data_dir: str = "."):
        self.data_dir = Path(data_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._stock: dict[str, StockItem] = {}
        self._thresholds: dict[str, Threshold] = {}
        self._alerts_log: list[dict] = []
        self._load_config()

    def _config_path(self) -> Path:
        return self.data_dir / "inventory_config.json"

    def _load_config(self):
        path = self._config_path()
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                for t in data.get("thresholds", []):
                    self._thresholds[t["sku"]] = Threshold(**t)
            except (json.JSONDecodeError, OSError, KeyError):
                pass

    def _save_config(self):
        data = {
            "thresholds": [
                {"sku": t.sku, "min_qty": t.min_qty,
                 "reorder_qty": t.reorder_qty, "max_qty": t.max_qty,
                 "auto_po": t.auto_po}
                for t in self._thresholds.values()
            ]
        }
        self._config_path().write_text(
            json.dumps(data, indent=2), encoding="utf-8")

    def load_stock(self, csv_path: str) -> dict:
        path = Path(csv_path)
        if not path.exists():
            raise FileNotFoundError(f"Stock CSV not found: {csv_path}")

        with open(path, encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                return {"status": "error", "reason": "empty CSV"}

            col_map = self._map_columns(reader.fieldnames)
            count = 0
            for row in reader:
                item = self._row_to_item(row, col_map)
                if item:
                    self._stock[item.sku] = item
                    count += 1

        return {"status": "loaded", "items": count}

    def _map_columns(self, headers: list[str]) -> dict[str, str]:
        mapping = {}
        normalized = {h: h.strip().lower().replace(" ", "_") for h in headers}
        for field_name, aliases in STOCK_COLUMN_ALIASES.items():
            for header, norm in normalized.items():
                if norm in aliases:
                    mapping[field_name] = header
                    break
        return mapping

    def _row_to_item(self, row: dict, col_map: dict) -> StockItem | None:
        sku_col = col_map.get("sku")
        name_col = col_map.get("name")
        qty_col = col_map.get("quantity")
        if not sku_col and not name_col:
            return None

        sku = row.get(sku_col, "").strip() if sku_col else ""
        name = row.get(name_col, "").strip() if name_col else sku
        if not sku and not name:
            return None
        if not sku:
            sku = name.lower().replace(" ", "_")[:32]

        qty_raw = row.get(qty_col, "0").strip() if qty_col else "0"
        try:
            qty = int(float(qty_raw))
        except ValueError:
            qty = 0

        cost_col = col_map.get("unit_cost")
        try:
            cost = float(row.get(cost_col, "0").strip().replace(",", "").replace("$", "")) if cost_col else 0.0
        except ValueError:
            cost = 0.0

        return StockItem(
            sku=sku, name=name, quantity=qty, unit_cost=cost,
            category=row.get(col_map.get("category", ""), "").strip(),
            vendor=row.get(col_map.get("vendor", ""), "").strip(),
        )

    def set_threshold(self, sku: str, min_qty: int,
                      reorder_qty: int, max_qty: int = 0,
                      auto_po: bool = False):
        self._thresholds[sku] = Threshold(
            sku=sku, min_qty=min_qty, reorder_qty=reorder_qty,
            max_qty=max_qty, auto_po=auto_po)
        self._save_config()

    def set_default_threshold(self, min_qty: int = 10,
                              reorder_qty: int = 50):
        for sku in self._stock:
            if sku not in self._thresholds:
                self._thresholds[sku] = Threshold(
                    sku=sku, min_qty=min_qty, reorder_qty=reorder_qty)
        self._save_config()

    def check_thresholds(self) -> list[StockAlert]:
        alerts = []
        for sku, threshold in self._thresholds.items():
            item = self._stock.get(sku)
            if not item:
                continue
            if item.quantity <= threshold.min_qty:
                shortfall = threshold.reorder_qty - item.quantity
                severity = "CRITICAL" if item.quantity == 0 else \
                           "HIGH" if item.quantity <= threshold.min_qty // 2 else "MEDIUM"
                alerts.append(StockAlert(
                    sku=sku, name=item.name,
                    current_qty=item.quantity,
                    min_qty=threshold.min_qty,
                    reorder_qty=threshold.reorder_qty,
                    shortfall=max(shortfall, 0),
                    unit_cost=item.unit_cost,
                    severity=severity,
                ))

        return sorted(alerts, key=lambda a: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(a.severity, 3),
            -a.shortfall))

    def generate_po(self, alerts: list[StockAlert],
                    vendor: str = "",
                    po_prefix: str = "PO") -> PurchaseOrder | None:
        if not alerts:
            return None

        now = datetime.now(timezone.utc)
        po_number = f"{po_prefix}-{now.strftime('%Y%m%d-%H%M%S')}"

        items = []
        total = 0.0
        for a in alerts:
            line_total = a.shortfall * a.unit_cost
            items.append({
                "sku": a.sku,
                "name": a.name,
                "quantity": a.shortfall,
                "unit_cost": a.unit_cost,
                "line_total": round(line_total, 2),
            })
            total += line_total

        vendor_name = vendor
        if not vendor_name:
            vendors = [self._stock[a.sku].vendor for a in alerts
                       if a.sku in self._stock and self._stock[a.sku].vendor]
            vendor_name = vendors[0] if vendors else "TBD"

        po = PurchaseOrder(
            po_number=po_number,
            vendor=vendor_name,
            date=now.strftime("%Y-%m-%d"),
            items=items,
            total=round(total, 2),
        )

        po_path = self.data_dir / f"{po_number}.json"
        po_path.write_text(json.dumps(po_to_dict(po), indent=2),
                           encoding="utf-8")
        return po

    def send_slack_alert(self, webhook_url: str,
                         alerts: list[StockAlert]) -> bool:
        if not alerts:
            return True
        lines = ["*Inventory Alert* :warning:"]
        for a in alerts:
            lines.append(f"• *{a.severity}* `{a.sku}` {a.name}: "
                         f"{a.current_qty} remaining (min: {a.min_qty}, "
                         f"reorder: {a.shortfall} units)")
        payload = json.dumps({"text": "\n".join(lines)}).encode("utf-8")
        req = urllib.request.Request(
            webhook_url, data=payload,
            headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=10)
            return True
        except (urllib.error.URLError, OSError):
            return False

    def send_email_alert(self, alerts: list[StockAlert],
                         to_addr: str, from_addr: str,
                         smtp_host: str = "localhost",
                         smtp_port: int = 587,
                         smtp_user: str = "", smtp_pass: str = "") -> bool:
        if not alerts:
            return True

        body = "Attestor Inventory Alert\n" + "=" * 40 + "\n\n"
        for a in alerts:
            body += (f"[{a.severity}] {a.sku} - {a.name}\n"
                     f"  Current: {a.current_qty}, Min: {a.min_qty}, "
                     f"Reorder: {a.shortfall} units\n"
                     f"  Est cost: ${a.shortfall * a.unit_cost:,.2f}\n\n")

        msg = MIMEText(body)
        msg["Subject"] = f"Attestor: {len(alerts)} inventory alert(s)"
        msg["From"] = from_addr
        msg["To"] = to_addr

        try:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as s:
                if smtp_user:
                    s.starttls()
                    s.login(smtp_user, smtp_pass)
                s.send_message(msg)
            return True
        except (smtplib.SMTPException, OSError):
            return False

    def get_stock(self) -> dict[str, StockItem]:
        return dict(self._stock)

    def get_low_stock(self) -> list[StockItem]:
        low = []
        for sku, t in self._thresholds.items():
            item = self._stock.get(sku)
            if item and item.quantity <= t.min_qty:
                low.append(item)
        return sorted(low, key=lambda i: i.quantity)

    def render_alerts(self, alerts: list[StockAlert]) -> str:
        if not alerts:
            return "  No inventory alerts."
        lines = [
            "\n  Inventory Alerts",
            "  " + "=" * 55,
            f"  {len(alerts)} item(s) below threshold\n",
        ]
        for a in alerts:
            est = f"${a.shortfall * a.unit_cost:,.2f}" if a.unit_cost else "N/A"
            lines.append(f"  {a.severity:8s}  {a.sku:20s}  "
                         f"qty={a.current_qty} (min={a.min_qty})")
            lines.append(f"           {a.name}")
            lines.append(f"           reorder {a.shortfall} units  est: {est}")
            lines.append("")
        lines.append("  " + "=" * 55)
        return "\n".join(lines)


def po_to_dict(po: PurchaseOrder) -> dict:
    return {
        "po_number": po.po_number,
        "vendor": po.vendor,
        "date": po.date,
        "items": po.items,
        "total": po.total,
        "status": po.status,
    }


def alerts_to_dict(alerts: list[StockAlert]) -> list[dict]:
    return [
        {"sku": a.sku, "name": a.name, "current_qty": a.current_qty,
         "min_qty": a.min_qty, "reorder_qty": a.reorder_qty,
         "shortfall": a.shortfall, "unit_cost": a.unit_cost,
         "severity": a.severity}
        for a in alerts
    ]
