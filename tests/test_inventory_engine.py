"""Tests for inventory monitoring engine."""
import json
import os
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detector"))
import inventory_engine


def _make_stock_csv(root, items):
    path = os.path.join(root, "stock.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        f.write("sku,name,quantity,unit_cost,category,vendor\n")
        for item in items:
            f.write(",".join(str(v) for v in item) + "\n")
    return path


SAMPLE_STOCK = [
    ("WDG-001", "Widget A", 100, 5.99, "Widgets", "Acme"),
    ("WDG-002", "Widget B", 8, 12.50, "Widgets", "Acme"),
    ("GDG-001", "Gadget X", 0, 25.00, "Gadgets", "Beta Corp"),
    ("GDG-002", "Gadget Y", 45, 8.75, "Gadgets", "Beta Corp"),
    ("SPR-001", "Sprocket", 3, 2.50, "Parts", "Gamma Inc"),
]


def test_load_stock():
    root = tempfile.mkdtemp()
    try:
        csv_path = _make_stock_csv(root, SAMPLE_STOCK)
        mon = inventory_engine.InventoryMonitor(root)
        result = mon.load_stock(csv_path)
        assert result["status"] == "loaded"
        assert result["items"] == 5
    finally:
        shutil.rmtree(root)


def test_load_stock_missing():
    root = tempfile.mkdtemp()
    try:
        mon = inventory_engine.InventoryMonitor(root)
        try:
            mon.load_stock(os.path.join(root, "nope.csv"))
            assert False
        except FileNotFoundError:
            pass
    finally:
        shutil.rmtree(root)


def test_set_threshold():
    root = tempfile.mkdtemp()
    try:
        mon = inventory_engine.InventoryMonitor(root)
        mon.set_threshold("WDG-001", min_qty=20, reorder_qty=100)
        assert "WDG-001" in mon._thresholds
        assert mon._thresholds["WDG-001"].min_qty == 20
    finally:
        shutil.rmtree(root)


def test_check_thresholds():
    root = tempfile.mkdtemp()
    try:
        csv_path = _make_stock_csv(root, SAMPLE_STOCK)
        mon = inventory_engine.InventoryMonitor(root)
        mon.load_stock(csv_path)
        mon.set_threshold("WDG-002", min_qty=10, reorder_qty=50)
        mon.set_threshold("GDG-001", min_qty=5, reorder_qty=30)
        mon.set_threshold("SPR-001", min_qty=10, reorder_qty=100)
        alerts = mon.check_thresholds()
        assert len(alerts) == 3
        skus = [a.sku for a in alerts]
        assert "GDG-001" in skus
        assert "WDG-002" in skus
        assert "SPR-001" in skus
    finally:
        shutil.rmtree(root)


def test_alert_severity():
    root = tempfile.mkdtemp()
    try:
        csv_path = _make_stock_csv(root, SAMPLE_STOCK)
        mon = inventory_engine.InventoryMonitor(root)
        mon.load_stock(csv_path)
        mon.set_threshold("GDG-001", min_qty=5, reorder_qty=30)
        alerts = mon.check_thresholds()
        gadget_alert = [a for a in alerts if a.sku == "GDG-001"][0]
        assert gadget_alert.severity == "CRITICAL"
    finally:
        shutil.rmtree(root)


def test_no_alerts():
    root = tempfile.mkdtemp()
    try:
        csv_path = _make_stock_csv(root, SAMPLE_STOCK)
        mon = inventory_engine.InventoryMonitor(root)
        mon.load_stock(csv_path)
        mon.set_threshold("WDG-001", min_qty=5, reorder_qty=50)
        alerts = mon.check_thresholds()
        assert len(alerts) == 0
    finally:
        shutil.rmtree(root)


def test_generate_po():
    root = tempfile.mkdtemp()
    try:
        csv_path = _make_stock_csv(root, SAMPLE_STOCK)
        mon = inventory_engine.InventoryMonitor(root)
        mon.load_stock(csv_path)
        mon.set_threshold("WDG-002", min_qty=10, reorder_qty=50)
        mon.set_threshold("GDG-001", min_qty=5, reorder_qty=30)
        alerts = mon.check_thresholds()
        po = mon.generate_po(alerts, vendor="Acme Corp")
        assert po is not None
        assert po.vendor == "Acme Corp"
        assert len(po.items) == 2
        assert po.total > 0
    finally:
        shutil.rmtree(root)


def test_generate_po_empty():
    root = tempfile.mkdtemp()
    try:
        mon = inventory_engine.InventoryMonitor(root)
        po = mon.generate_po([])
        assert po is None
    finally:
        shutil.rmtree(root)


def test_default_threshold():
    root = tempfile.mkdtemp()
    try:
        csv_path = _make_stock_csv(root, SAMPLE_STOCK)
        mon = inventory_engine.InventoryMonitor(root)
        mon.load_stock(csv_path)
        mon.set_default_threshold(min_qty=10, reorder_qty=50)
        assert len(mon._thresholds) == 5
    finally:
        shutil.rmtree(root)


def test_get_low_stock():
    root = tempfile.mkdtemp()
    try:
        csv_path = _make_stock_csv(root, SAMPLE_STOCK)
        mon = inventory_engine.InventoryMonitor(root)
        mon.load_stock(csv_path)
        mon.set_default_threshold(min_qty=10, reorder_qty=50)
        low = mon.get_low_stock()
        assert len(low) >= 2
        assert low[0].quantity <= low[-1].quantity
    finally:
        shutil.rmtree(root)


def test_render_alerts():
    root = tempfile.mkdtemp()
    try:
        csv_path = _make_stock_csv(root, SAMPLE_STOCK)
        mon = inventory_engine.InventoryMonitor(root)
        mon.load_stock(csv_path)
        mon.set_threshold("GDG-001", min_qty=5, reorder_qty=30)
        alerts = mon.check_thresholds()
        text = mon.render_alerts(alerts)
        assert "CRITICAL" in text
        assert "GDG-001" in text
    finally:
        shutil.rmtree(root)


def test_render_no_alerts():
    root = tempfile.mkdtemp()
    try:
        mon = inventory_engine.InventoryMonitor(root)
        text = mon.render_alerts([])
        assert "No inventory alerts" in text
    finally:
        shutil.rmtree(root)


def test_config_persistence():
    root = tempfile.mkdtemp()
    try:
        mon1 = inventory_engine.InventoryMonitor(root)
        mon1.set_threshold("SKU-A", min_qty=10, reorder_qty=50)
        mon2 = inventory_engine.InventoryMonitor(root)
        assert "SKU-A" in mon2._thresholds
        assert mon2._thresholds["SKU-A"].min_qty == 10
    finally:
        shutil.rmtree(root)


def test_po_to_dict():
    po = inventory_engine.PurchaseOrder(
        po_number="PO-001", vendor="Test", date="2026-09-01",
        items=[{"sku": "A", "quantity": 10, "unit_cost": 5.0, "line_total": 50.0}],
        total=50.0)
    d = inventory_engine.po_to_dict(po)
    assert d["po_number"] == "PO-001"
    assert d["total"] == 50.0


def test_alerts_to_dict():
    alert = inventory_engine.StockAlert(
        sku="A", name="Item A", current_qty=2, min_qty=10,
        reorder_qty=50, shortfall=48, unit_cost=5.0, severity="CRITICAL")
    d = inventory_engine.alerts_to_dict([alert])
    assert len(d) == 1
    assert d[0]["severity"] == "CRITICAL"
