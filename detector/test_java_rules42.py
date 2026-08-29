#!/usr/bin/env python3
"""Java rules, tested the way the C rules were: against their own corrections.

Every case is a pair. The flawed form must be reported and the corrected form
must not, because a rule that fires on both is worth nothing however plausible
it looks -- that is the lesson `format-string` taught, where a rule that
matched the sink shape reported the fix as often as the defect and scored zero
against ground truth.

There is no Java corpus here yet. SARD ships Juliet Java 1.3 with 28,881 test
cases, which is the measurement these rules deserve; until it is downloaded
these pairs are hand-written and prove discrimination, not coverage.
"""
from __future__ import annotations

import unittest

import detect

LANGUAGE = "java"


def findings(source: str, rule: str | None = None):
    found = detect.scan_source(source, "T.java", LANGUAGE, deep=True)
    return [f for f in found if rule is None or f.rule == rule]


def wrap(body: str) -> str:
    return "public class T {\n    void run() throws Exception {\n%s\n    }\n}\n" % body


class OtherSinksTheSameValueMustNotReach(unittest.TestCase):
    """Four more places a value from outside lands, all one question.

    Each asks what the SQL rule asks -- is a tainted name inside this call's
    arguments -- so each is a pair for the same reason: the corrected half
    keeps the identical sink and changes only where the value came from, or
    escapes it on the way.
    """

    def pair(self, rule, flawed, fixed):
        with self.subTest(rule=rule, form="flawed"):
            self.assertTrue(findings(wrap(flawed), rule),
                            "%s did not report the defect" % rule)
        with self.subTest(rule=rule, form="fixed"):
            self.assertFalse(findings(wrap(fixed), rule),
                             "%s fires on the correction too" % rule)

    def test_ldap_injection(self):
        sink = ('        DirContext dc = new InitialDirContext(env);\n'
                '        String search = "(cn=" + data + ")";\n'
                '        NamingEnumeration answer = dc.search("", search, null);\n')
        self.pair("java-ldap-injection",
                  '        String data = System.getenv("ADD");\n' + sink,
                  '        String data = "foo";\n' + sink)

    def test_ldap_rule_stays_out_of_files_that_are_not_talking_to_a_directory(self):
        # `.search(` is far too common a method name to report on its own.
        self.assertFalse(findings(wrap(
            '        String data = System.getenv("ADD");\n'
            '        int at = haystack.search(data);\n'), "java-ldap-injection"))

    def test_xpath_injection(self):
        head = ('        XPath xPath = XPathFactory.newInstance().newXPath();\n')
        self.pair(
            "java-xpath-injection",
            '        String data = System.getenv("ADD");\n' + head +
            '        String query = "//u[name=\'" + data + "\']";\n'
            '        String s = (String)xPath.evaluate(query, xml, STRING);\n',
            '        String data = System.getenv("ADD");\n' + head +
            '        String safe = StringEscapeUtils.escapeXml(data);\n'
            '        String query = "//u[name=\'" + safe + "\']";\n'
            '        String s = (String)xPath.evaluate(query, xml, STRING);\n')

    def test_reflected_xss(self):
        sink = '        response.getWriter().println("<br>" + data);\n'
        self.pair("java-xss-reflected",
                  '        String data = request.getParameter("q");\n' + sink,
                  '        String data = "foo";\n' + sink)

    def test_a_blacklist_is_not_an_escaper(self):
        """Juliet's CWE-80 flawed half filters, and is still the defect.

        `replaceAll("(<script>)", "")` removes one spelling of one tag. If it
        counted as a fix the rule would go quiet on the exact case the corpus
        ships to catch.
        """
        self.assertTrue(findings(wrap(
            '        String data = request.getParameter("q");\n'
            '        response.getWriter().println("<br>"'
            ' + data.replaceAll("(<script>)", ""));\n'),
            "java-xss-reflected"))

    def test_response_splitting(self):
        self.pair(
            "java-response-splitting",
            '        String data = request.getParameter("q");\n'
            '        response.addHeader("Location", "/a.jsp?l=" + data);\n',
            '        String data = request.getParameter("q");\n'
            '        data = URLEncoder.encode(data, "UTF-8");\n'
            '        response.addHeader("Location", "/a.jsp?l=" + data);\n')

    def test_response_splitting_accepts_encoding_at_the_sink_itself(self):
        self.assertFalse(findings(wrap(
            '        String data = request.getParameter("q");\n'
            '        Cookie c = new Cookie("lang",'
            ' URLEncoder.encode(data, "UTF-8"));\n'),
            "java-response-splitting"))


class BoundsAndArithmetic(unittest.TestCase):
    """The families where the guard is the whole discriminator.

    CWE-129, 190, 191 and 369 are 20,171 of Juliet Java's files and had no
    rule at all. Both halves of a case perform the identical operation; only
    the corrected one tests its value first. So every case below is a pair
    where the *operation is the same on both sides* -- that is the only shape
    that proves the rule keys on the check rather than the arithmetic.
    """

    def pair(self, rule, unguarded, guarded):
        with self.subTest(rule=rule, form="unguarded"):
            self.assertTrue(findings(wrap(unguarded), rule),
                            "%s did not report the unguarded use" % rule)
        with self.subTest(rule=rule, form="guarded"):
            self.assertFalse(findings(wrap(guarded), rule),
                             "%s fires even when the value is checked" % rule)

    def test_array_index_needs_both_ends(self):
        # The flawed half *does* check the length. What it omits is zero, and
        # a negative index is what actually throws.
        self.pair(
            "java-array-index-unchecked",
            '        int data = Integer.parseInt(System.getenv("N"));\n'
            '        if (data < array.length) {\n'
            '            IO.writeLine(array[data]);\n'
            '        }\n',
            '        int data = Integer.parseInt(System.getenv("N"));\n'
            '        if (data >= 0 && data < array.length) {\n'
            '            IO.writeLine(array[data]);\n'
            '        }\n')

    def test_divisor_checked_against_zero(self):
        self.pair(
            "java-divide-by-zero",
            '        int data = Integer.parseInt(System.getenv("N"));\n'
            '        int result = 100 / data;\n',
            '        int data = Integer.parseInt(System.getenv("N"));\n'
            '        if (data != 0) {\n'
            '            int result = 100 / data;\n'
            '        }\n')

    def test_a_float_divisor_is_guarded_by_epsilon_not_by_zero(self):
        """`!= 0` is the wrong guard for a float and Juliet knows it.

        The corrected variant writes `Math.abs(data) > 0.000001`, because a
        float divisor is dangerous well before it reaches exactly zero.
        Matching only `!= 0` left this rule firing on the corrected half of
        44% of pairs -- worse than not having the rule.
        """
        self.assertFalse(findings(wrap(
            '        float data = Float.parseFloat(System.getenv("N"));\n'
            '        if (Math.abs(data) > 0.000001) {\n'
            '            int result = (int)(100.0 / data);\n'
            '        }\n'), "java-divide-by-zero"))

    def test_narrowing_arithmetic_needs_a_limit_check(self):
        self.pair(
            "java-integer-overflow",
            '        byte data = Byte.parseByte(System.getenv("N"));\n'
            '        byte result = (byte)(data * 2);\n',
            '        byte data = Byte.parseByte(System.getenv("N"));\n'
            '        if (data < Byte.MAX_VALUE / 2) {\n'
            '            byte result = (byte)(data * 2);\n'
            '        }\n')

    def test_the_variable_being_assigned_is_not_an_operand(self):
        """The guard names the input; the result is tainted by definition.

        `byte result = (byte)(data + 1)` computes `result` from `data`, so
        `result` is tainted too -- and a guard on `data` says nothing about a
        name that did not exist when it ran. Scanning the whole line found
        `result` unguarded and reported correctly-written code: it was every
        one of the 4% of CWE-190 pairs this rule fired on both halves of.
        """
        self.assertFalse(findings(wrap(
            '        byte data = Byte.parseByte(System.getenv("N"));\n'
            '        if (data < Byte.MAX_VALUE) {\n'
            '            byte result = (byte)(data + 1);\n'
            '        }\n'), "java-integer-overflow"))

    def test_plain_arithmetic_is_not_reported(self):
        # Restricted to narrowing casts on purpose: `a + b` on a tainted value
        # is most of the arithmetic in most programs, and a rule that fired on
        # all of it would report the corrected variant just as loudly.
        self.assertFalse(findings(wrap(
            '        int data = Integer.parseInt(System.getenv("N"));\n'
            '        int total = data + 1;\n'), "java-integer-overflow"))

    def test_a_literal_index_is_not_reported(self):
        self.assertFalse(findings(wrap(
            '        int data = 2;\n'
            '        IO.writeLine(array[data]);\n'), "java-array-index-unchecked"))

    def test_strictly_positive_counts_as_a_lower_bound(self):
        """`> 0` is stronger than `>= 0` and has to be accepted as well.

        Only `>=` was matched, so on every Juliet case whose fix reads
        `if (data > 0)` the rule reported the *corrected* half and said
        nothing about the flawed one -- 22% of held-out CWE-129 pairs came
        back inverted, which is a worse failure than missing them.
        """
        for guard in ("data > 0 && data < array.length",
                      "0 < data && data < array.length",
                      "data >= 0 && data < array.length"):
            with self.subTest(guard=guard):
                self.assertFalse(findings(wrap(
                    '        int data = Integer.parseInt(System.getenv("N"));\n'
                    '        if (%s) {\n'
                    '            IO.writeLine(array[data]);\n'
                    '        }\n' % guard), "java-array-index-unchecked"))


class AllocationSizeMustBeBounded(unittest.TestCase):
    """CWE-789 -- 2,553 Juliet files, and no rule covered any of them.

    Both halves allocate. The flawed one sizes the allocation with a value
    that arrived from outside; the corrected one uses a literal. Not one of
    the 941 single-flow files fixes the flaw with a check, so these pairs
    carry the guarded shapes the corpus never exercises.
    """

    ALLOC = '        ArrayList list = new ArrayList(data);\n'

    def test_a_size_from_outside_is_reported(self):
        self.assertTrue(findings(wrap(
            '        int data = Integer.parseInt(System.getenv("N"));\n'
            + self.ALLOC), "java-unbounded-allocation"))

    def test_a_literal_size_is_not(self):
        self.assertFalse(findings(wrap(
            '        int data = 2;\n' + self.ALLOC),
            "java-unbounded-allocation"))

    def test_a_ceiling_clears_it(self):
        for guard in ("data < 1000", "data <= 1000", "1000 > data"):
            with self.subTest(guard=guard):
                self.assertFalse(findings(wrap(
                    '        int data = Integer.parseInt(System.getenv("N"));\n'
                    '        if (%s) {\n' % guard
                    + '    ' + self.ALLOC +
                    '        }\n'), "java-unbounded-allocation"))

    def test_config_files_are_a_source_too(self):
        """`properties.getProperty(...)` is external input, same as getenv.

        Only `System.getProperty` was matched, so the whole PropertiesFile
        third of the family read as untainted and stayed silent.
        """
        self.assertTrue(findings(wrap(
            '        String n = properties.getProperty("data");\n'
            '        int data = Integer.parseInt(n.trim());\n'
            + self.ALLOC), "java-unbounded-allocation"))

    def test_an_unbounded_random_draw_is_a_size_nobody_capped(self):
        self.assertTrue(findings(wrap(
            '        int data = (new SecureRandom()).nextInt();\n'
            + self.ALLOC), "java-unbounded-allocation"))

    def test_a_bounded_random_draw_is_not(self):
        """`nextInt(100)` cannot exceed 100 -- the argument is the ceiling."""
        self.assertFalse(findings(wrap(
            '        int data = (new SecureRandom()).nextInt(100);\n'
            + self.ALLOC), "java-unbounded-allocation"))

    def test_arrays_count_as_well_as_collections(self):
        self.assertTrue(findings(wrap(
            '        int data = Integer.parseInt(System.getenv("N"));\n'
            '        byte[] buffer = new byte[data];\n'),
            "java-unbounded-allocation"))

    def test_the_collection_itself_is_not_the_defect(self):
        """An `ArrayList` is not a finding; one sized from outside is."""
        self.assertFalse(findings(wrap(
            '        ArrayList list = new ArrayList();\n'
            '        HashMap seen = new HashMap(16);\n'),
            "java-unbounded-allocation"))


class HowLongThisRunsMustBeBounded(unittest.TestCase):
    """CWE-400 -- 2,412 files. The loop is identical on both sides.

    Only the corrected variant bounds its counter first, so these pairs are
    written with the *same* loop on both sides; anything that keys on the
    loop itself rather than the guard would pass the flawed case and fail
    the corrected one just as loudly.
    """

    LOOP = ('        for (i = 0; i < count; i++) {\n'
            '            IO.writeLine("Hello");\n'
            '        }\n')

    def test_a_loop_counted_from_outside_is_reported(self):
        self.assertTrue(findings(wrap(
            '        int count = Integer.parseInt(System.getenv("ADD"));\n'
            + self.LOOP), "java-unbounded-loop"))

    def test_the_same_loop_with_a_ceiling_is_not(self):
        self.assertFalse(findings(wrap(
            '        int count = Integer.parseInt(System.getenv("ADD"));\n'
            '        if (count > 0 && count <= 20) {\n'
            + self.LOOP +
            '        }\n'), "java-unbounded-loop"))

    def test_a_literal_count_is_not_reported(self):
        self.assertFalse(findings(wrap(
            '        int count = 2;\n' + self.LOOP), "java-unbounded-loop"))

    def test_iterating_a_collection_is_not_a_finding(self):
        """`i < data.length` is how every correct loop in Java is written.

        The capture cannot span the dot, which is what keeps this rule off
        the ordinary case -- worth an explicit test, because a rule that
        reported every for-loop over tainted data would be unusable.
        """
        self.assertFalse(findings(wrap(
            '        String data = System.getenv("ADD");\n'
            '        for (int i = 0; i < data.length(); i++) {\n'
            '            IO.writeLine("x");\n'
            '        }\n'), "java-unbounded-loop"))

    def test_sleeping_for_an_outside_duration_is_the_same_defect(self):
        self.assertTrue(findings(wrap(
            '        int count = Integer.parseInt(System.getenv("ADD"));\n'
            '        Thread.sleep(count);\n'), "java-unbounded-loop"))

    def test_a_bounded_sleep_is_not(self):
        self.assertFalse(findings(wrap(
            '        int count = Integer.parseInt(System.getenv("ADD"));\n'
            '        if (count > 0 && count <= 2000) {\n'
            '            Thread.sleep(count);\n'
            '        }\n'), "java-unbounded-loop"))

    def test_max_value_needs_no_attacker(self):
        """Nothing can make `Integer.MAX_VALUE` smaller.

        It is not tainted -- no attacker supplied it -- but a loop counted to
        it is unbounded by construction, and Juliet's corrected variant
        guards it exactly as if it had come from outside.
        """
        self.assertTrue(findings(wrap(
            '        int count = Integer.MAX_VALUE;\n'
            '        Thread.sleep(count);\n'), "java-unbounded-loop"))
        self.assertFalse(findings(wrap(
            '        int count = Integer.MAX_VALUE;\n'
            '        if (count > 0 && count <= 2000) {\n'
            '            Thread.sleep(count);\n'
            '        }\n'), "java-unbounded-loop"))

    def test_min_value_initialisation_is_not_a_finding(self):
        """Juliet opens all 875 of these with `count = Integer.MIN_VALUE`.

        Treating MAX and MIN alike would report every file on both halves.
        """
        self.assertFalse(findings(wrap(
            '        int count = Integer.MIN_VALUE;\n'
            '        Thread.sleep(count);\n'), "java-unbounded-loop"))

    def test_a_dead_branch_does_not_bound_a_random_count(self):
        """The `_02` shape: the clear is in a branch the sink never runs with.

        Tracked outside the taint walker this missed every one of them --
        the same failure the branch merge was written for, repeated in a set
        that was not participating in it.
        """
        self.assertTrue(findings(wrap(
            '        int count;\n'
            '        if (IO.staticReturnsTrueOrFalse()) {\n'
            '            count = (new SecureRandom()).nextInt();\n'
            '        } else {\n'
            '            count = 0;\n'
            '        }\n' + self.LOOP), "java-unbounded-loop"))

    def test_a_bounded_random_count_is_not_reported(self):
        self.assertFalse(findings(wrap(
            '        int count = (new SecureRandom()).nextInt(100);\n'
            + self.LOOP), "java-unbounded-loop"))


class NarrowingCastsDiscardBits(unittest.TestCase):
    """CWE-197 -- 1,996 files. The cast is identical on both sides.

    Not one of the 726 single-flow cases fixes the flaw with a range check;
    the corrected variant swaps the source for a literal and keeps the same
    `(byte) data`. So this is a taint question wearing a type-system hat.
    """

    def test_a_value_from_outside_narrowed_to_a_byte(self):
        self.assertTrue(findings(wrap(
            '        int data = Integer.parseInt(System.getenv("ADD"));\n'
            '        IO.writeLine((byte)data);\n'), "java-numeric-truncation"))

    def test_the_same_cast_on_a_literal_is_not_reported(self):
        self.assertFalse(findings(wrap(
            '        int data = 2;\n'
            '        IO.writeLine((byte)data);\n'), "java-numeric-truncation"))

    def test_widening_is_never_a_finding(self):
        """`(long) intValue` cannot lose anything, however tainted it is.

        Whether a cast truncates depends on the declared width of the
        operand, which is the reason declarations are tracked at all -- a
        rule keyed on the cast alone would report every widening conversion
        in the codebase.
        """
        for decl, cast in (("int", "long"), ("short", "int"),
                           ("byte", "short"), ("float", "double")):
            with self.subTest(decl=decl, cast=cast):
                self.assertFalse(findings(wrap(
                    '        %s data = %s.parseInt(System.getenv("N"));\n'
                    '        IO.writeLine((%s)data);\n'
                    % (decl, "Integer", cast)), "java-numeric-truncation"))

    def test_short_to_byte_is_still_a_narrowing(self):
        self.assertTrue(findings(wrap(
            '        short data = Short.parseShort(System.getenv("N"));\n'
            '        IO.writeLine((byte)data);\n'), "java-numeric-truncation"))

    def test_a_row_out_of_the_database_is_input(self):
        """`resultSet.getString()` was not a source, so every `_database`
        variant across every family read as clean."""
        self.assertTrue(findings(wrap(
            '        String s = resultSet.getString(1);\n'
            '        int data = Integer.parseInt(s.trim());\n'
            '        IO.writeLine((byte)data);\n'), "java-numeric-truncation"))


class MoreSinksTheSameValueMustNotReach(unittest.TestCase):
    """One taint engine, five more sinks. 4,548 files that had no rule.

    Every one of these families corrects the flaw the same way the injection
    families do -- the call stays identical and only the source changes -- so
    each pair below keeps the sink fixed on both sides.
    """

    def pair(self, rule, sink):
        tainted = ('        String data = System.getenv("ADD");\n' + sink)
        literal = ('        String data = "foo";\n' + sink)
        with self.subTest(rule=rule, half="flawed"):
            self.assertTrue(findings(wrap(tainted), rule))
        with self.subTest(rule=rule, half="corrected"):
            self.assertFalse(findings(wrap(literal), rule))

    def test_format_string(self):
        self.pair("java-format-string", '        System.out.format(data);\n')

    def test_a_value_formatted_as_an_argument_is_correct_usage(self):
        """`String.format("%s", data)` is the fix, not the defect.

        A rule keyed on `format(` with anything tainted nearby would report
        the correct spelling just as loudly as the wrong one.
        """
        self.assertFalse(findings(wrap(
            '        String data = System.getenv("ADD");\n'
            '        String out = String.format("%s", data);\n'),
            "java-format-string"))

    def test_absolute_path_traversal(self):
        self.pair("java-path-traversal",
                  '        File file = new File(data);\n')

    def test_relative_path_traversal(self):
        """`new File(root + data)` -- joining a base does not contain it."""
        self.pair("java-path-traversal",
                  '        File file = new File("/home/app/" + data);\n')

    def test_unsafe_reflection(self):
        self.pair("java-unsafe-reflection",
                  '        Class<?> c = Class.forName(data);\n')

    def test_external_configuration(self):
        self.pair("java-external-config",
                  '        dbConnection.setCatalog(data);\n')

    def test_an_error_page_is_a_response_body(self):
        """CWE-81. `sendError` writes the message into the generated page.

        It scored 0% while the attribute-context variant scored 100%, purely
        because that one goes through `getWriter()` and this one does not.
        """
        self.pair("java-xss-reflected",
                  '        response.sendError(404, "bad " + data);\n')

    def test_each_new_rule_stays_out_of_the_others_files(self):
        """A file that opens a path is not a reflection finding, and so on."""
        source = wrap('        String data = System.getenv("ADD");\n'
                      '        File file = new File(data);\n')
        rules = {f.rule for f in findings(source)}
        self.assertIn("java-path-traversal", rules)
        for other in ("java-unsafe-reflection", "java-external-config",
                      "java-format-string"):
            self.assertNotIn(other, rules)


class PatternFamilies(unittest.TestCase):
    """Defects you can see in one line, and the correct spelling beside each.

    Every pair keeps everything except the construct itself identical, so a
    rule that keyed on the surrounding shape rather than the defect would
    fail the second half.
    """

    def pair(self, rule, flawed, fixed):
        with self.subTest(rule=rule, half="flawed"):
            self.assertTrue(findings(wrap(flawed), rule))
        with self.subTest(rule=rule, half="corrected"):
            self.assertFalse(findings(wrap(fixed), rule))

    def test_string_compared_by_identity(self):
        self.pair("java-string-identity-compare",
                  '        String a = "x";\n        String b = "y";\n'
                  '        if (a == b) { IO.writeLine("same"); }\n',
                  '        String a = "x";\n        String b = "y";\n'
                  '        if (a.equals(b)) { IO.writeLine("same"); }\n')

    def test_null_and_number_comparisons_are_not_reported(self):
        """`== null` and `== 0` are the correct uses of ==."""
        for line in ('        if (data == null) { return; }\n',
                     '        if (count == 0) { return; }\n'):
            self.assertFalse(findings(wrap(line),
                                      "java-string-identity-compare"))

    def test_weak_prng(self):
        self.pair("java-weak-prng",
                  '        int n = (new Random()).nextInt();\n',
                  '        int n = (new SecureRandom()).nextInt();\n')

    def test_broken_cipher(self):
        """The algorithm is a *string*, so this rule reads ctx.literal.

        Against blanked code both halves are `getInstance("      ")` and the
        rule scored 0% -- it was looking at text with the answer removed.
        """
        self.pair("java-broken-cipher",
                  '        KeyGenerator k = KeyGenerator.getInstance("DESede");\n',
                  '        KeyGenerator k = KeyGenerator.getInstance("AES");\n')

    def test_suspicious_comment(self):
        self.assertTrue(findings(wrap('        // TODO: check the input\n'),
                                 "java-suspicious-comment"))
        self.assertFalse(findings(wrap('        // reads the input\n'),
                                  "java-suspicious-comment"))

    def test_system_exit(self):
        self.pair("java-system-exit",
                  '        System.exit(1);\n',
                  '        throw new IllegalStateException("stopping");\n')

    def test_overbroad_catch(self):
        self.pair("java-overbroad-catch",
                  '        try { f(); } catch (Exception e) { log(e); }\n',
                  '        try { f(); } catch (IOException e) { log(e); }\n')

    def test_generic_throw(self):
        self.pair("java-generic-throw",
                  '        throw new Exception("broke");\n',
                  '        throw new IOException("broke");\n')

    def test_explicit_finalize(self):
        self.pair("java-explicit-finalize",
                  '        obj.finalize();\n',
                  '        obj.close();\n')

    def test_obsolete_getbytes_overload(self):
        """The deprecated overload is told apart by its argument count."""
        self.pair("java-obsolete-api",
                  '        s.getBytes(0, len, out, 0);\n',
                  '        byte[] out = s.getBytes("UTF-8");\n')

    def test_insecure_cookie(self):
        self.pair("java-insecure-cookie",
                  '        Cookie c = new Cookie("k", data);\n'
                  '        response.addCookie(c);\n',
                  '        Cookie c = new Cookie("k", data);\n'
                  '        c.setSecure(true);\n'
                  '        response.addCookie(c);\n')

    def test_no_rule_claims_insecure_temp_files(self):
        """CWE-379/378 is deliberately uncovered.

        A rule keyed on `createTempFile` fired on both halves of every case
        -- the corrected variant creates the file in exactly the same place
        -- so it was deleted rather than shipped at 100% false positives.
        """
        self.assertNotIn("java-insecure-temp-file",
                         {getattr(fn, "name", None) for fn in detect.RULES})


class TaintCrossesFileBoundaries(unittest.TestCase):
    """Two files, one flow. 36% of Juliet's CWE-89 is written this way.

    `scan_project` runs a pass to learn which methods are handed a value
    from outside and which hand one back, then scans each file knowing it.
    A single-file scan cannot see either direction, and scored these zero.
    """

    SINK = (
        'public class Sink {\n'
        '    public void badSink(String data) throws Throwable {\n'
        '        Statement st = dbConnection.createStatement();\n'
        '        st.addBatch("update users set x=1 where name=\'" + data + "\'");\n'
        '    }\n'
        '}\n')

    def project(self, caller):
        return detect.scan_project(
            {"Caller.java": caller, "Sink.java": self.SINK}, deep=True)

    def rule_fired(self, findings_list):
        return any(f.rule == "java-sql-injection" for f in findings_list)

    def test_a_source_in_one_file_reaches_a_sink_in_another(self):
        self.assertTrue(self.rule_fired(self.project(
            'public class Caller {\n'
            '    public void bad() throws Throwable {\n'
            '        String data = System.getenv("ADD");\n'
            '        (new Sink()).badSink(data);\n'
            '    }\n'
            '}\n')))

    def test_a_literal_passed_across_the_boundary_is_not_a_finding(self):
        """The corrected half of every one of these cases.

        If passing a literal seeded the sink too, the rule would report both
        halves and discriminate nothing -- which is the failure the whole
        differential criterion exists to catch.
        """
        self.assertFalse(self.rule_fired(self.project(
            'public class Caller {\n'
            '    public void goodG2B() throws Throwable {\n'
            '        String data = "foo";\n'
            '        (new Sink()).badSink(data);\n'
            '    }\n'
            '}\n')))

    def test_scanning_the_sink_alone_still_finds_nothing(self):
        """Cross-file taint must come from the project pass, not from thin air."""
        self.assertFalse(self.rule_fired(
            detect.scan_source(self.SINK, "Sink.java", "java", deep=True)))

    def test_taint_returned_from_another_file(self):
        """The other direction: the source is over there, the sink is here."""
        source_file = (
            'public class Source {\n'
            '    public String badSource() throws Throwable {\n'
            '        String data = System.getenv("ADD");\n'
            '        return data;\n'
            '    }\n'
            '}\n')
        caller = (
            'public class Caller {\n'
            '    public void bad() throws Throwable {\n'
            '        String data = (new Source()).badSource();\n'
            '        Statement st = dbConnection.createStatement();\n'
            '        st.addBatch("update users set x=1 where n=\'" + data + "\'");\n'
            '    }\n'
            '}\n')
        self.assertTrue(self.rule_fired(detect.scan_project(
            {"Source.java": source_file, "Caller.java": caller}, deep=True)))

    def test_a_value_carried_across_in_an_array(self):
        """`dataArray[2] = data` was not parsed as an assignment at all."""
        self.assertTrue(self.rule_fired(self.project(
            'public class Caller {\n'
            '    public void bad() throws Throwable {\n'
            '        String data = System.getenv("ADD");\n'
            '        String[] dataArray = new String[5];\n'
            '        dataArray[2] = data;\n'
            '        (new Sink()).badSink(dataArray[2]);\n'
            '    }\n'
            '}\n')))

    def test_a_value_carried_across_in_a_list(self):
        self.assertTrue(self.rule_fired(self.project(
            'public class Caller {\n'
            '    public void bad() throws Throwable {\n'
            '        String data = System.getenv("ADD");\n'
            '        LinkedList<String> holder = new LinkedList<String>();\n'
            '        holder.add(data);\n'
            '        (new Sink()).badSink(holder.get(0));\n'
            '    }\n'
            '}\n')))

    def test_one_file_alone_is_scanned_exactly_as_before(self):
        """A single-file project must not gain cross-file behaviour."""
        lone = ('public class Sink {\n'
                '    public void badSink(String data) throws Throwable {\n'
                '        Runtime.getRuntime().exec(data);\n'
                '    }\n'
                '}\n')
        self.assertEqual(
            [f.rule for f in detect.scan_project({"Sink.java": lone}, deep=True)],
            [f.rule for f in detect.scan_source(lone, "Sink.java", "java",
                                                deep=True)])

    def test_a_same_named_method_elsewhere_does_not_taint_this_one(self):
        """The seed is a bare method name, so this is the cost of that choice.

        A file only honours a name it declares itself, and passing a literal
        never seeds anything -- so an unrelated `badSink` reached only with
        literals stays quiet.
        """
        other = ('public class Other {\n'
                 '    public void unrelated() throws Throwable {\n'
                 '        (new Sink()).badSink("literal");\n'
                 '    }\n'
                 '}\n')
        self.assertFalse(self.rule_fired(detect.scan_project(
            {"Other.java": other, "Sink.java": self.SINK}, deep=True)))


class TaintCrossesMethodBoundaries(unittest.TestCase):
    """A source in one method reaching a sink in another.

    Every one of these was silent until the flow was resolved, and every one
    is a shape ordinary Java takes constantly -- a helper that reads input, a
    sink that takes the value as a parameter, a field holding it in between.
    Each case is still a pair: carrying a *literal* across the same boundary
    must stay quiet, or the flow analysis has only made the rule louder.
    """

    def scan(self, body, rule="java-sql-injection"):
        return findings("public class T {\n%s}\n" % body, rule)

    SINK = ('        st.executeQuery("SELECT * FROM t WHERE a = " + data);\n')

    def test_a_parameter_carries_taint_in(self):
        self.assertTrue(self.scan(
            '    void bad() throws Exception {\n'
            '        String data = System.getenv("X");\n'
            '        badSink(data);\n'
            '    }\n'
            '    void badSink(String data) throws Exception {\n'
            + self.SINK +
            '    }\n'))

    def test_a_literal_argument_does_not(self):
        self.assertFalse(self.scan(
            '    void good() throws Exception {\n'
            '        String data = "42";\n'
            '        goodSink(data);\n'
            '    }\n'
            '    void goodSink(String data) throws Exception {\n'
            + self.SINK +
            '    }\n'))

    def test_a_returned_value_carries_taint_out(self):
        self.assertTrue(self.scan(
            '    void bad() throws Exception {\n'
            '        String data = badSource();\n'
            + self.SINK +
            '    }\n'
            '    String badSource() throws Exception {\n'
            '        String got = System.getenv("X");\n'
            '        return got;\n'
            '    }\n'))

    def test_a_returned_literal_does_not(self):
        self.assertFalse(self.scan(
            '    void good() throws Exception {\n'
            '        String data = goodSource();\n'
            + self.SINK +
            '    }\n'
            '    String goodSource() throws Exception {\n'
            '        String got = "42";\n'
            '        return got;\n'
            '    }\n'))

    def test_a_field_carries_taint_though_the_sink_is_declared_first(self):
        # The ordering is the point: a single forward walk reaches the sink
        # while the assignment that taints the field is still in the future,
        # which is why the field pass repeats until it settles.
        self.assertTrue(self.scan(
            '    private String data;\n'
            '    void badSink() throws Exception {\n'
            + self.SINK +
            '    }\n'
            '    void bad() throws Exception {\n'
            '        data = System.getenv("X");\n'
            '        badSink();\n'
            '    }\n'))

    def test_a_field_holding_a_literal_does_not(self):
        self.assertFalse(self.scan(
            '    private String data;\n'
            '    void goodSink() throws Exception {\n'
            + self.SINK +
            '    }\n'
            '    void good() throws Exception {\n'
            '        data = "42";\n'
            '        goodSink();\n'
            '    }\n'))


class Discrimination(unittest.TestCase):
    """Each pair: the defect fires, the correction does not."""

    def assert_pair(self, rule, flawed, fixed):
        with self.subTest(rule=rule, form="flawed"):
            self.assertTrue(findings(wrap(flawed), rule),
                            "%s did not report the defect" % rule)
        with self.subTest(rule=rule, form="fixed"):
            self.assertFalse(findings(wrap(fixed), rule),
                             "%s also fires on the correction, so it "
                             "discriminates nothing" % rule)

    def test_command_injection(self):
        self.assert_pair(
            "java-command-injection",
            '        String tag = System.getenv("TAG");\n'
            '        Runtime.getRuntime().exec("git push origin " + tag);',
            '        String tag = System.getenv("TAG");\n'
            '        new ProcessBuilder(java.util.List.of("git", "push", tag)).start();')

    def test_command_injection_ignores_a_fixed_command(self):
        self.assertFalse(findings(
            wrap('        Runtime.getRuntime().exec("ls -la");'),
            "java-command-injection"))

    def test_sql_injection(self):
        self.assert_pair(
            "java-sql-injection",
            '        String id = request.getParameter("id");\n'
            '        st.executeQuery("SELECT * FROM t WHERE id = " + id);',
            '        String id = request.getParameter("id");\n'
            '        PreparedStatement p = c.prepareStatement("SELECT * FROM t WHERE id = ?");\n'
            '        p.setString(1, id);\n'
            '        p.executeQuery();')

    def test_sql_injection_ignores_a_bound_statement(self):
        self.assertFalse(findings(
            wrap('        p.executeQuery();'), "java-sql-injection"))

    def test_a_literal_source_is_not_reported(self):
        """The discriminator these two rules live or die by.

        Juliet's `goodG2B` keeps the identical concatenation at the sink and
        changes only where the value came from. Matching the sink shape alone
        reported the correction as often as the defect and scored zero, which
        is why the taint gate exists -- and why it is worth a test of its own.
        A corruption that silently disabled that gate cost 35 points on
        CWE-89 and 77 on CWE-78 while every other test still passed.
        """
        for rule, body in (
            ("java-sql-injection",
             '        String id = "42";\n'
             '        st.executeQuery("SELECT * FROM t WHERE id = " + id);'),
            ("java-command-injection",
             '        String tag = "v1";\n'
             '        Runtime.getRuntime().exec("git push origin " + tag);'),
        ):
            with self.subTest(rule=rule):
                self.assertFalse(findings(wrap(body), rule))

    def test_fixed_seed(self):
        self.assert_pair(
            "java-fixed-seed",
            '        SecureRandom r = new SecureRandom();\n'
            '        r.setSeed(SEED);',
            '        SecureRandom r = new SecureRandom();')

    def test_fixed_seed_accepts_a_seed_that_varies(self):
        # Weak for other reasons, but not this defect, and the two have
        # different fixes -- reporting both here would blur them.
        self.assertFalse(findings(wrap(
            '        SecureRandom r = new SecureRandom();\n'
            '        r.setSeed(System.currentTimeMillis());'),
            "java-fixed-seed"))

    def test_fixed_seed_covers_a_numeric_literal(self):
        self.assertTrue(findings(wrap('        r.setSeed(12345L);'),
                                 "java-fixed-seed"))

    def test_weak_hash(self):
        self.assert_pair(
            "java-weak-hash",
            '        MessageDigest.getInstance("MD5");',
            '        MessageDigest.getInstance("SHA-256");')

    def test_weak_hash_covers_sha1_and_hmac(self):
        for name in ('"SHA-1"', '"HmacMD5"', '"md5"'):
            with self.subTest(algorithm=name):
                self.assertTrue(findings(
                    wrap("        MessageDigest.getInstance(%s);" % name),
                    "java-weak-hash"))

    def test_insecure_deserialisation(self):
        self.assert_pair(
            "java-insecure-deserialize",
            '        Object o = new ObjectInputStream(in).readObject();',
            '        Object o = new com.fasterxml.jackson.databind.ObjectMapper().readValue(in, Dto.class);')

    def test_weak_random(self):
        self.assert_pair(
            "java-weak-random",
            '        String token = Long.toString(new Random().nextLong());',
            '        String token = Long.toString(new java.security.SecureRandom().nextLong());')

    def test_weak_random_leaves_ordinary_randomness_alone(self):
        # A shuffle, a jitter or test data is not a defect, and reporting it
        # would make the rule noise.
        self.assertFalse(findings(
            wrap('        int roll = new Random().nextInt(6);'),
            "java-weak-random"))

    def test_xxe(self):
        flawed = (
            '        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n'
            '        f.newDocumentBuilder().parse(input);')
        fixed = (
            '        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n'
            '        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n'
            '        f.newDocumentBuilder().parse(input);')
        self.assert_pair("java-xxe", flawed, fixed)


class NotFooledByCommentsOrStrings(unittest.TestCase):
    """The blanking has to work, or every rule matches its own documentation."""

    def test_a_comment_is_not_a_finding(self):
        source = wrap('        // Runtime.getRuntime().exec("git " + tag);')
        self.assertFalse(findings(source, "java-command-injection"))

    def test_a_block_comment_is_not_a_finding(self):
        source = wrap('        /* MessageDigest.getInstance("MD5"); */')
        self.assertFalse(findings(source, "java-weak-hash"))

    def test_a_string_literal_is_not_a_finding(self):
        source = wrap('        String doc = "call executeQuery(\\"x\\" + y)";')
        self.assertFalse(findings(source, "java-sql-injection"))


class LanguageWiring(unittest.TestCase):
    def test_java_files_resolve_to_the_java_language(self):
        self.assertEqual(detect.language_for("Deploy.java"), "java")

    def test_java_is_reported_as_covered(self):
        import language_coverage42 as coverage
        self.assertIn("java", coverage.covered_languages())

    def test_the_wildcard_rules_still_run_on_java(self):
        # Making Java a language must not lose the secret scanning it had
        # while it was classified as text.
        source = wrap('        String password = "hunter2hunter2hunter2";')
        self.assertTrue(detect.scan_source(source, "T.java", "java",
                                           deep=True))

    def test_every_java_rule_has_a_cwe(self):
        for candidate in detect.RULES:
            if "java" in (getattr(candidate, "langs", ()) or ()):
                with self.subTest(rule=candidate.rid):
                    self.assertTrue(getattr(candidate, "cwe", ""),
                                    "%s has no CWE mapping" % candidate.rid)


class NoFalsePositivesOnOrdinaryJava(unittest.TestCase):
    """Plain, correct Java must produce nothing from the Java rules."""

    CLEAN = """public class Service {
    private final Repository repo;

    public Service(Repository repo) {
        this.repo = repo;
    }

    public List<Order> recent(int limit) throws Exception {
        PreparedStatement p = repo.connection().prepareStatement(
            "SELECT id, total FROM orders WHERE created > ? LIMIT ?");
        p.setTimestamp(1, cutoff());
        p.setInt(2, limit);
        MessageDigest.getInstance("SHA-256");
        return map(p.executeQuery());
    }
}
"""

    def test_clean_service_class(self):
        java_rules = {r.rid for r in detect.RULES
                      if "java" in (getattr(r, "langs", ()) or ())}
        reported = [f.rule for f in
                    detect.scan_source(self.CLEAN, "S.java", "java", deep=True)
                    if f.rule in java_rules]
        self.assertEqual(reported, [], "false positives: %s" % reported)


if __name__ == "__main__":
    unittest.main(verbosity=2)
