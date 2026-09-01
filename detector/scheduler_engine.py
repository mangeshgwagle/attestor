#!/usr/bin/env python3
"""Employee scheduling engine -- constraint-based shift assignment.

Assigns staff to shifts using rules: availability, role requirements,
max hours, labour cost caps. No LLM -- pure constraint solving.

    from scheduler_engine import Scheduler
    s = Scheduler()
    s.add_employee("Alice", roles=["cashier","stock"], hours_available={0:[9,17],1:[9,17]})
    s.add_shift("Mon AM", day=0, start=9, end=13, role="cashier")
    schedule = s.solve()
"""
from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

DAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday",
             "Friday", "Saturday", "Sunday"]


@dataclass
class Employee:
    name: str
    roles: list[str] = field(default_factory=list)
    hours_available: dict[int, list[int]] = field(default_factory=dict)
    max_hours_week: float = 40.0
    hourly_rate: float = 15.0
    priority: int = 0
    email: str = ""


@dataclass
class Shift:
    shift_id: str
    day: int
    start_hour: int
    end_hour: int
    role: str = ""
    min_staff: int = 1
    max_staff: int = 1
    location: str = ""


@dataclass
class Assignment:
    shift: Shift
    employee: Employee
    hours: float
    cost: float


@dataclass
class Schedule:
    week_start: str
    assignments: list[Assignment]
    unassigned: list[Shift]
    total_hours: float
    total_cost: float
    conflicts: list[str]
    by_employee: dict[str, list[dict]]
    by_day: dict[str, list[dict]]


class Scheduler:
    def __init__(self):
        self._employees: dict[str, Employee] = {}
        self._shifts: list[Shift] = []
        self._labour_cap: float = 0.0

    def add_employee(self, name: str, roles: list[str] | None = None,
                     hours_available: dict[int, list[int]] | None = None,
                     max_hours_week: float = 40.0,
                     hourly_rate: float = 15.0,
                     priority: int = 0, email: str = ""):
        self._employees[name] = Employee(
            name=name,
            roles=roles or [],
            hours_available=hours_available or {},
            max_hours_week=max_hours_week,
            hourly_rate=hourly_rate,
            priority=priority,
            email=email,
        )

    def add_shift(self, shift_id: str, day: int, start_hour: int,
                  end_hour: int, role: str = "", min_staff: int = 1,
                  max_staff: int = 1, location: str = ""):
        self._shifts.append(Shift(
            shift_id=shift_id, day=day, start_hour=start_hour,
            end_hour=end_hour, role=role, min_staff=min_staff,
            max_staff=max_staff, location=location,
        ))

    def set_labour_cap(self, weekly_cap: float):
        self._labour_cap = weekly_cap

    def load_employees_csv(self, path: str) -> int:
        with open(path, encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                name = (row.get("name") or row.get("employee") or "").strip()
                if not name:
                    continue
                roles_raw = (row.get("roles") or row.get("role") or "").strip()
                roles = [r.strip() for r in roles_raw.split(",") if r.strip()]

                avail = {}
                for d in range(7):
                    key = DAY_NAMES[d].lower()[:3]
                    val = (row.get(key) or row.get(DAY_NAMES[d].lower()) or "").strip()
                    if val and val.lower() not in ("off", "no", "n/a", ""):
                        try:
                            parts = val.split("-")
                            if len(parts) == 2:
                                avail[d] = [int(parts[0]), int(parts[1])]
                            else:
                                avail[d] = [9, 17]
                        except ValueError:
                            avail[d] = [9, 17]

                rate_raw = (row.get("rate") or row.get("hourly_rate") or
                           row.get("pay") or "15").strip()
                try:
                    rate = float(rate_raw.replace("$", "").replace(",", ""))
                except ValueError:
                    rate = 15.0

                max_h = float(row.get("max_hours", "40") or "40")

                self.add_employee(
                    name=name, roles=roles, hours_available=avail,
                    max_hours_week=max_h, hourly_rate=rate,
                    email=(row.get("email") or "").strip(),
                )
                count += 1
        return count

    def load_shifts_csv(self, path: str) -> int:
        with open(path, encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            count = 0
            for row in reader:
                sid = (row.get("shift_id") or row.get("shift") or
                       row.get("id") or f"shift_{count}").strip()
                day_raw = (row.get("day") or "0").strip()
                try:
                    day = int(day_raw)
                except ValueError:
                    day_map = {n.lower(): i for i, n in enumerate(DAY_NAMES)}
                    day_map.update({n.lower()[:3]: i for i, n in enumerate(DAY_NAMES)})
                    day = day_map.get(day_raw.lower(), 0)

                start = int(row.get("start", row.get("start_hour", "9")))
                end = int(row.get("end", row.get("end_hour", "17")))
                role = (row.get("role") or "").strip()
                min_s = int(row.get("min_staff", "1"))
                max_s = int(row.get("max_staff", "1"))

                self.add_shift(sid, day, start, end, role, min_s, max_s)
                count += 1
        return count

    def _can_work(self, employee: Employee, shift: Shift) -> bool:
        if shift.role and shift.role not in employee.roles:
            return False
        if shift.day not in employee.hours_available:
            return False
        avail = employee.hours_available[shift.day]
        if len(avail) >= 2:
            if shift.start_hour < avail[0] or shift.end_hour > avail[1]:
                return False
        return True

    def _shift_hours(self, shift: Shift) -> float:
        return max(shift.end_hour - shift.start_hour, 0)

    def _shifts_overlap(self, a: Shift, b: Shift) -> bool:
        if a.day != b.day:
            return False
        return a.start_hour < b.end_hour and b.start_hour < a.end_hour

    def solve(self, week_start: str = "") -> Schedule:
        if not week_start:
            today = datetime.now()
            monday = today - timedelta(days=today.weekday())
            week_start = monday.strftime("%Y-%m-%d")

        assignments: list[Assignment] = []
        unassigned: list[Shift] = []
        conflicts: list[str] = []
        emp_hours: dict[str, float] = {e: 0.0 for e in self._employees}
        emp_shifts: dict[str, list[Shift]] = {e: [] for e in self._employees}
        total_cost = 0.0

        sorted_shifts = sorted(self._shifts,
                               key=lambda s: (s.day, s.start_hour))

        for shift in sorted_shifts:
            hours = self._shift_hours(shift)
            assigned_count = 0

            candidates = sorted(
                self._employees.values(),
                key=lambda e: (e.priority, emp_hours.get(e.name, 0),
                               e.hourly_rate))

            for emp in candidates:
                if assigned_count >= shift.max_staff:
                    break

                if not self._can_work(emp, shift):
                    continue

                if emp_hours[emp.name] + hours > emp.max_hours_week:
                    continue

                overlap = any(self._shifts_overlap(shift, s)
                              for s in emp_shifts[emp.name])
                if overlap:
                    continue

                if self._labour_cap > 0:
                    projected = total_cost + hours * emp.hourly_rate
                    if projected > self._labour_cap:
                        conflicts.append(
                            f"Labour cap would be exceeded assigning "
                            f"{emp.name} to {shift.shift_id}")
                        continue

                cost = hours * emp.hourly_rate
                assignments.append(Assignment(
                    shift=shift, employee=emp,
                    hours=hours, cost=round(cost, 2)))
                emp_hours[emp.name] += hours
                emp_shifts[emp.name].append(shift)
                total_cost += cost
                assigned_count += 1

            if assigned_count < shift.min_staff:
                unassigned.append(shift)
                conflicts.append(
                    f"{shift.shift_id} ({DAY_NAMES[shift.day]}) needs "
                    f"{shift.min_staff} staff, only {assigned_count} assigned")

        by_employee: dict[str, list[dict]] = {}
        for a in assignments:
            name = a.employee.name
            if name not in by_employee:
                by_employee[name] = []
            by_employee[name].append({
                "shift": a.shift.shift_id,
                "day": DAY_NAMES[a.shift.day],
                "start": a.shift.start_hour,
                "end": a.shift.end_hour,
                "hours": a.hours,
                "cost": a.cost,
                "role": a.shift.role,
            })

        by_day: dict[str, list[dict]] = {}
        for a in assignments:
            day = DAY_NAMES[a.shift.day]
            if day not in by_day:
                by_day[day] = []
            by_day[day].append({
                "shift": a.shift.shift_id,
                "employee": a.employee.name,
                "start": a.shift.start_hour,
                "end": a.shift.end_hour,
                "role": a.shift.role,
            })

        return Schedule(
            week_start=week_start,
            assignments=assignments,
            unassigned=unassigned,
            total_hours=round(sum(emp_hours.values()), 1),
            total_cost=round(total_cost, 2),
            conflicts=conflicts,
            by_employee=by_employee,
            by_day=by_day,
        )

    def render(self, schedule: Schedule) -> str:
        lines = [
            f"\n  Weekly Schedule (week of {schedule.week_start})",
            "  " + "=" * 55,
            f"  Total hours: {schedule.total_hours}h  |  "
            f"Cost: ${schedule.total_cost:,.2f}",
        ]

        for day in DAY_NAMES:
            shifts = schedule.by_day.get(day, [])
            if not shifts:
                continue
            lines.append(f"\n  {day}:")
            for s in sorted(shifts, key=lambda x: x["start"]):
                role = f" [{s['role']}]" if s["role"] else ""
                lines.append(f"    {s['start']:02d}:00-{s['end']:02d}:00  "
                             f"{s['employee']}{role}")

        if schedule.conflicts:
            lines.append(f"\n  Conflicts ({len(schedule.conflicts)}):")
            for c in schedule.conflicts:
                lines.append(f"    ! {c}")

        if schedule.unassigned:
            lines.append(f"\n  Unassigned shifts ({len(schedule.unassigned)}):")
            for s in schedule.unassigned:
                lines.append(f"    {s.shift_id} ({DAY_NAMES[s.day]} "
                             f"{s.start_hour:02d}:00-{s.end_hour:02d}:00) "
                             f"role={s.role}")

        lines.append("\n  Per-employee summary:")
        for name, shifts in sorted(schedule.by_employee.items()):
            total_h = sum(s["hours"] for s in shifts)
            total_c = sum(s["cost"] for s in shifts)
            lines.append(f"    {name:20s}  {total_h:5.1f}h  ${total_c:>8,.2f}  "
                         f"({len(shifts)} shifts)")

        lines.append("  " + "=" * 55)
        return "\n".join(lines)


def to_dict(schedule: Schedule) -> dict:
    return {
        "week_start": schedule.week_start,
        "total_hours": schedule.total_hours,
        "total_cost": schedule.total_cost,
        "by_employee": schedule.by_employee,
        "by_day": schedule.by_day,
        "conflicts": schedule.conflicts,
        "unassigned": [
            {"shift_id": s.shift_id, "day": DAY_NAMES[s.day],
             "start": s.start_hour, "end": s.end_hour, "role": s.role}
            for s in schedule.unassigned
        ],
    }


def to_gcal_events(schedule: Schedule,
                   week_start: str = "") -> list[dict]:
    if not week_start:
        week_start = schedule.week_start
    base = datetime.strptime(week_start, "%Y-%m-%d")
    events = []
    for a in schedule.assignments:
        day_dt = base + timedelta(days=a.shift.day)
        start = day_dt.replace(hour=a.shift.start_hour, minute=0)
        end = day_dt.replace(hour=a.shift.end_hour, minute=0)
        role = f" [{a.shift.role}]" if a.shift.role else ""
        events.append({
            "summary": f"{a.employee.name}{role}",
            "start": {"dateTime": start.isoformat(), "timeZone": "UTC"},
            "end": {"dateTime": end.isoformat(), "timeZone": "UTC"},
            "description": (f"Shift: {a.shift.shift_id}\n"
                            f"Role: {a.shift.role}\n"
                            f"Hours: {a.hours}h\n"
                            f"Cost: ${a.cost:.2f}"),
        })
    return events
