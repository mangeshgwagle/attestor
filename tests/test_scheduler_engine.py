"""Tests for employee scheduling engine."""
import os
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detector"))
import scheduler_engine


def _basic_scheduler():
    s = scheduler_engine.Scheduler()
    s.add_employee("Alice", roles=["cashier", "stock"],
                   hours_available={0: [9, 17], 1: [9, 17], 2: [9, 17],
                                    3: [9, 17], 4: [9, 17]},
                   hourly_rate=18.0)
    s.add_employee("Bob", roles=["cashier"],
                   hours_available={0: [12, 20], 1: [12, 20], 2: [12, 20]},
                   hourly_rate=15.0)
    s.add_employee("Carol", roles=["stock", "manager"],
                   hours_available={0: [9, 17], 2: [9, 17], 4: [9, 17]},
                   hourly_rate=22.0, max_hours_week=24.0)
    return s


def test_basic_solve():
    s = _basic_scheduler()
    s.add_shift("Mon AM", day=0, start_hour=9, end_hour=13, role="cashier")
    s.add_shift("Mon PM", day=0, start_hour=13, end_hour=17, role="cashier")
    schedule = s.solve()
    assert len(schedule.assignments) == 2
    assert schedule.total_hours > 0
    assert schedule.total_cost > 0


def test_no_overlap():
    s = _basic_scheduler()
    s.add_shift("Mon AM", day=0, start_hour=9, end_hour=13, role="cashier")
    s.add_shift("Mon Full", day=0, start_hour=9, end_hour=17, role="cashier")
    schedule = s.solve()
    emp_assignments = {}
    for a in schedule.assignments:
        name = a.employee.name
        if name not in emp_assignments:
            emp_assignments[name] = []
        emp_assignments[name].append(a.shift)
    for name, shifts in emp_assignments.items():
        for i, s1 in enumerate(shifts):
            for s2 in shifts[i+1:]:
                if s1.day == s2.day:
                    assert not (s1.start_hour < s2.end_hour and
                               s2.start_hour < s1.end_hour), \
                        f"{name} has overlapping shifts"


def test_role_constraint():
    s = scheduler_engine.Scheduler()
    s.add_employee("Alice", roles=["cashier"],
                   hours_available={0: [9, 17]})
    s.add_shift("Mon AM", day=0, start_hour=9, end_hour=13, role="manager")
    schedule = s.solve()
    assert len(schedule.assignments) == 0
    assert len(schedule.unassigned) == 1


def test_availability_constraint():
    s = scheduler_engine.Scheduler()
    s.add_employee("Alice", roles=["cashier"],
                   hours_available={0: [9, 17]})
    s.add_shift("Tue AM", day=1, start_hour=9, end_hour=13, role="cashier")
    schedule = s.solve()
    assert len(schedule.assignments) == 0
    assert len(schedule.unassigned) == 1


def test_max_hours():
    s = scheduler_engine.Scheduler()
    s.add_employee("Alice", roles=["cashier"],
                   hours_available={i: [9, 17] for i in range(5)},
                   max_hours_week=16.0)
    for day in range(5):
        s.add_shift(f"Day{day}", day=day, start_hour=9, end_hour=17,
                    role="cashier")
    schedule = s.solve()
    alice_hours = sum(a.hours for a in schedule.assignments
                      if a.employee.name == "Alice")
    assert alice_hours <= 16.0


def test_labour_cap():
    s = _basic_scheduler()
    s.set_labour_cap(100.0)
    for day in range(5):
        s.add_shift(f"Day{day}", day=day, start_hour=9, end_hour=17,
                    role="cashier")
    schedule = s.solve()
    assert schedule.total_cost <= 100.0 or len(schedule.conflicts) > 0


def test_render():
    s = _basic_scheduler()
    s.add_shift("Mon AM", day=0, start_hour=9, end_hour=13, role="cashier")
    schedule = s.solve()
    text = s.render(schedule)
    assert "Monday" in text
    assert "Total hours" in text


def test_to_dict():
    s = _basic_scheduler()
    s.add_shift("Mon AM", day=0, start_hour=9, end_hour=13, role="cashier")
    schedule = s.solve()
    d = scheduler_engine.to_dict(schedule)
    assert "week_start" in d
    assert "by_employee" in d
    assert "by_day" in d
    assert "total_cost" in d


def test_to_gcal_events():
    s = _basic_scheduler()
    s.add_shift("Mon AM", day=0, start_hour=9, end_hour=13, role="cashier")
    schedule = s.solve("2026-09-07")
    events = scheduler_engine.to_gcal_events(schedule)
    assert len(events) >= 1
    assert "summary" in events[0]
    assert "start" in events[0]
    assert "end" in events[0]
    assert "dateTime" in events[0]["start"]


def test_multiple_staff():
    s = scheduler_engine.Scheduler()
    s.add_employee("Alice", roles=["cashier"],
                   hours_available={0: [9, 17]}, hourly_rate=18.0)
    s.add_employee("Bob", roles=["cashier"],
                   hours_available={0: [9, 17]}, hourly_rate=15.0)
    s.add_shift("Mon AM", day=0, start_hour=9, end_hour=13,
                role="cashier", min_staff=2, max_staff=2)
    schedule = s.solve()
    mon_am = [a for a in schedule.assignments
              if a.shift.shift_id == "Mon AM"]
    assert len(mon_am) == 2


def test_unassigned_tracking():
    s = scheduler_engine.Scheduler()
    s.add_shift("Mon AM", day=0, start_hour=9, end_hour=13, role="pilot")
    schedule = s.solve()
    assert len(schedule.unassigned) == 1
    assert schedule.unassigned[0].shift_id == "Mon AM"
    assert len(schedule.conflicts) >= 1


def test_by_employee_view():
    s = _basic_scheduler()
    s.add_shift("Mon AM", day=0, start_hour=9, end_hour=13, role="cashier")
    s.add_shift("Tue AM", day=1, start_hour=9, end_hour=13, role="cashier")
    schedule = s.solve()
    assert len(schedule.by_employee) >= 1
    for name, shifts in schedule.by_employee.items():
        for shift in shifts:
            assert "day" in shift
            assert "start" in shift
            assert "hours" in shift


def test_by_day_view():
    s = _basic_scheduler()
    s.add_shift("Mon AM", day=0, start_hour=9, end_hour=13, role="cashier")
    schedule = s.solve()
    assert "Monday" in schedule.by_day
    assert len(schedule.by_day["Monday"]) >= 1


def test_empty_schedule():
    s = scheduler_engine.Scheduler()
    schedule = s.solve()
    assert schedule.total_hours == 0
    assert schedule.total_cost == 0
    assert len(schedule.assignments) == 0


def test_load_employees_csv():
    root = tempfile.mkdtemp()
    try:
        path = os.path.join(root, "staff.csv")
        with open(path, "w") as f:
            f.write("name,roles,rate,max_hours,mon,tue,wed\n")
            f.write("Alice,\"cashier,stock\",18,40,9-17,9-17,9-17\n")
            f.write("Bob,cashier,15,40,12-20,12-20,off\n")
        s = scheduler_engine.Scheduler()
        count = s.load_employees_csv(path)
        assert count == 2
        assert "Alice" in s._employees
        assert "Bob" in s._employees
        assert 0 in s._employees["Alice"].hours_available
    finally:
        shutil.rmtree(root)


def test_load_shifts_csv():
    root = tempfile.mkdtemp()
    try:
        path = os.path.join(root, "shifts.csv")
        with open(path, "w") as f:
            f.write("shift_id,day,start,end,role,min_staff,max_staff\n")
            f.write("Mon AM,0,9,13,cashier,1,1\n")
            f.write("Mon PM,0,13,17,cashier,1,2\n")
        s = scheduler_engine.Scheduler()
        count = s.load_shifts_csv(path)
        assert count == 2
        assert len(s._shifts) == 2
    finally:
        shutil.rmtree(root)


def test_shifts_overlap():
    s = scheduler_engine.Scheduler()
    a = scheduler_engine.Shift("A", 0, 9, 13)
    b = scheduler_engine.Shift("B", 0, 12, 17)
    c = scheduler_engine.Shift("C", 0, 13, 17)
    d = scheduler_engine.Shift("D", 1, 9, 13)
    assert s._shifts_overlap(a, b) is True
    assert s._shifts_overlap(a, c) is False
    assert s._shifts_overlap(a, d) is False
