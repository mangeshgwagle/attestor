"""Tests for sales analysis engine."""
import json
import os
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detector"))
import sales_engine


def _make_csv(root, filename, headers, rows):
    path = os.path.join(root, filename)
    with open(path, "w", newline="", encoding="utf-8") as f:
        f.write(",".join(headers) + "\n")
        for row in rows:
            f.write(",".join(str(v) for v in row) + "\n")
    return path


def _sample_csv(root, days=30):
    from datetime import datetime, timedelta
    headers = ["date", "amount", "quantity", "product", "category", "order_id"]
    rows = []
    base = datetime(2026, 8, 1)
    for i in range(days):
        dt = base + timedelta(days=i)
        rows.append([dt.strftime("%Y-%m-%d"), 100 + i * 5, 2 + i % 3,
                     f"Product {i % 5}", f"Cat {i % 3}", f"ORD-{i:04d}"])
    return _make_csv(root, "sales.csv", headers, rows)


def test_ingest_csv():
    root = tempfile.mkdtemp()
    try:
        csv_path = _sample_csv(root)
        sa = sales_engine.SalesAnalyzer(root)
        result = sa.ingest(csv_path)
        assert result["status"] == "imported"
        assert result["rows"] == 30
    finally:
        shutil.rmtree(root)


def test_ingest_dedup():
    root = tempfile.mkdtemp()
    try:
        csv_path = _sample_csv(root)
        sa = sales_engine.SalesAnalyzer(root)
        sa.ingest(csv_path)
        result = sa.ingest(csv_path)
        assert result["status"] == "skipped"
    finally:
        shutil.rmtree(root)


def test_ingest_missing_file():
    root = tempfile.mkdtemp()
    try:
        sa = sales_engine.SalesAnalyzer(root)
        try:
            sa.ingest(os.path.join(root, "nope.csv"))
            assert False
        except FileNotFoundError:
            pass
    finally:
        shutil.rmtree(root)


def test_analyze_empty():
    root = tempfile.mkdtemp()
    try:
        sa = sales_engine.SalesAnalyzer(root)
        report = sa.analyze()
        assert report.total_revenue == 0
    finally:
        shutil.rmtree(root)


def test_analyze_with_data():
    root = tempfile.mkdtemp()
    try:
        csv_path = _sample_csv(root, days=30)
        sa = sales_engine.SalesAnalyzer(root)
        sa.ingest(csv_path)
        report = sa.analyze(days=90)
        assert report.total_revenue > 0
        assert report.total_units > 0
        assert report.total_orders > 0
    finally:
        shutil.rmtree(root)


def test_weekly_trends():
    root = tempfile.mkdtemp()
    try:
        csv_path = _sample_csv(root, days=21)
        sa = sales_engine.SalesAnalyzer(root)
        sa.ingest(csv_path)
        report = sa.analyze(days=90)
        assert len(report.weekly_trends) >= 2
        has_wow = any(t.wow_change is not None for t in report.weekly_trends)
        assert has_wow
    finally:
        shutil.rmtree(root)


def test_anomaly_detection():
    root = tempfile.mkdtemp()
    try:
        from datetime import datetime, timedelta
        headers = ["date", "amount", "quantity", "product", "order_id"]
        rows = []
        base = datetime(2026, 7, 1)
        for i in range(30):
            dt = base + timedelta(days=i)
            amount = 100 if i != 15 else 1000
            rows.append([dt.strftime("%Y-%m-%d"), amount, 1, "X", f"O{i}"])
        csv_path = _make_csv(root, "anomaly.csv", headers, rows)
        sa = sales_engine.SalesAnalyzer(root)
        sa.ingest(csv_path)
        report = sa.analyze(days=90)
        assert len(report.anomalies) >= 1
        spike = [a for a in report.anomalies if a.direction == "spike"]
        assert len(spike) >= 1
    finally:
        shutil.rmtree(root)


def test_forecast():
    root = tempfile.mkdtemp()
    try:
        csv_path = _sample_csv(root, days=30)
        sa = sales_engine.SalesAnalyzer(root)
        sa.ingest(csv_path)
        report = sa.analyze(days=90)
        assert len(report.forecasts) == 7
        for f in report.forecasts:
            assert f.predicted_revenue >= 0
            assert f.lower_bound <= f.predicted_revenue <= f.upper_bound
    finally:
        shutil.rmtree(root)


def test_top_products():
    root = tempfile.mkdtemp()
    try:
        csv_path = _sample_csv(root, days=20)
        sa = sales_engine.SalesAnalyzer(root)
        sa.ingest(csv_path)
        report = sa.analyze(days=90)
        assert len(report.top_products) >= 1
    finally:
        shutil.rmtree(root)


def test_render():
    root = tempfile.mkdtemp()
    try:
        csv_path = _sample_csv(root, days=30)
        sa = sales_engine.SalesAnalyzer(root)
        sa.ingest(csv_path)
        report = sa.analyze(days=90)
        text = sa.render(report)
        assert "Revenue" in text
        assert "$" in text
    finally:
        shutil.rmtree(root)


def test_to_dict():
    root = tempfile.mkdtemp()
    try:
        csv_path = _sample_csv(root, days=15)
        sa = sales_engine.SalesAnalyzer(root)
        sa.ingest(csv_path)
        report = sa.analyze(days=90)
        d = sales_engine.to_dict(report)
        assert "summary" in d
        assert "weekly_trends" in d
        assert "forecasts" in d
    finally:
        shutil.rmtree(root)


def test_clear():
    root = tempfile.mkdtemp()
    try:
        csv_path = _sample_csv(root, days=10)
        sa = sales_engine.SalesAnalyzer(root)
        sa.ingest(csv_path)
        assert sa.get_record_count() > 0
        sa.clear()
        assert sa.get_record_count() == 0
    finally:
        shutil.rmtree(root)


def test_column_aliases():
    root = tempfile.mkdtemp()
    try:
        headers = ["Order Date", "Total", "Qty", "Product Name"]
        rows = [["2026-08-01", "99.99", "3", "Widget"]]
        csv_path = _make_csv(root, "alt.csv", headers, rows)
        sa = sales_engine.SalesAnalyzer(root)
        result = sa.ingest(csv_path)
        assert result["status"] == "imported"
        assert result["rows"] == 1
    finally:
        shutil.rmtree(root)


def test_parse_date_formats():
    sa = sales_engine.SalesAnalyzer.__new__(sales_engine.SalesAnalyzer)
    assert sa._parse_date("2026-08-15") == "2026-08-15"
    assert sa._parse_date("08/15/2026") == "2026-08-15"
    assert sa._parse_date("2026-08-15T10:30:00") == "2026-08-15"
    assert sa._parse_date("not a date") is None


def test_parse_amount():
    sa = sales_engine.SalesAnalyzer.__new__(sales_engine.SalesAnalyzer)
    assert sa._parse_amount("$1,234.56") == 1234.56
    assert sa._parse_amount("99.99") == 99.99
    assert sa._parse_amount("-50.00") == -50.0
    assert sa._parse_amount("abc") is None
