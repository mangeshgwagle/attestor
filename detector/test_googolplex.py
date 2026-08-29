#!/usr/bin/env python3
"""Tests for googolplex.py -- writing the actual digits of 10**(10**100). Offline."""
import io
import unittest

import googolplex as g


class DigitTests(unittest.TestCase):
    def test_leading_digit_is_one(self):
        self.assertEqual(g.digit(0), "1")

    def test_every_other_digit_is_zero(self):
        self.assertEqual(g.digit(1), "0")
        self.assertEqual(g.digit(10 ** 50), "0")
        self.assertEqual(g.digit(g.GOOGOL), "0")          # the very last digit

    def test_out_of_range_positions_raise(self):
        with self.assertRaises(ValueError):
            g.digit(-1)
        with self.assertRaises(ValueError):
            g.digit(g.TOTAL_DIGITS)                        # one past the end

    def test_total_digit_count(self):
        self.assertEqual(g.TOTAL_DIGITS, 10 ** 100 + 1)


class WriteTests(unittest.TestCase):
    def test_first_five_digits(self):
        buf = io.StringIO()
        g.write(buf, 0, 5)
        self.assertEqual(buf.getvalue(), "10000")

    def test_writing_from_the_middle_is_all_zeros(self):
        buf = io.StringIO()
        g.write(buf, 10 ** 40, 1000)
        self.assertEqual(buf.getvalue(), "0" * 1000)

    def test_write_returns_the_count(self):
        buf = io.StringIO()
        self.assertEqual(g.write(buf, 0, 12345), 12345)

    def test_never_writes_past_the_end(self):
        buf = io.StringIO()
        written = g.write(buf, g.TOTAL_DIGITS - 3, 100)    # only 3 digits left
        self.assertEqual(written, 3)
        self.assertEqual(buf.getvalue(), "000")


class CliTests(unittest.TestCase):
    def test_count(self):
        buf = io.StringIO()
        with self._stdout(buf):
            g.main(["--count"])
        self.assertIn(str(10 ** 100 + 1), buf.getvalue())

    def test_at_a_huge_position(self):
        buf = io.StringIO()
        with self._stdout(buf):
            g.main(["--at", str(10 ** 99)])
        self.assertEqual(buf.getvalue().strip(), "0")

    def test_facts_are_printed(self):
        buf = io.StringIO()
        with self._stdout(buf):
            g.main(["--facts"])
        self.assertIn("googolplex", buf.getvalue())

    def _stdout(self, buf):
        from contextlib import redirect_stdout
        return redirect_stdout(buf)


if __name__ == "__main__":
    unittest.main(verbosity=2)
