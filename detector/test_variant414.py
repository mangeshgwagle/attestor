from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, replace
import hashlib
from pathlib import Path
import re
import unittest

import variant414 as variant


class Variant414Tests(unittest.TestCase):
    def test_exact_names_slugs_modes_and_default_are_stable(self) -> None:
        self.assertEqual(
            [
                (item.display_name, item.slug, item.mode)
                for item in variant.COMPILED_PROFILES
            ],
            [
                ("Cockroach Janta Party", "cockroach-janta-party", "maximum"),
                ("South Park", "south-park", "balanced"),
                ("Gruppe Sechs", "gruppe-sechs", "lightweight"),
            ],
        )
        self.assertIs(variant.DEFAULT_PROFILE, variant.SOUTH_PARK)
        self.assertEqual(
            variant.PROFILE_SLUGS,
            ("cockroach-janta-party", "south-park", "gruppe-sechs"))

    def test_compiled_profiles_and_registries_are_immutable(self) -> None:
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            variant.SOUTH_PARK.max_files = 1
        with self.assertRaises(TypeError):
            variant.PROFILES["new"] = variant.SOUTH_PARK
        with self.assertRaises(TypeError):
            variant.SECURITY_INVARIANTS["fail_closed"] = False
        with self.assertRaises(TypeError):
            variant.ALIASES["unsafe"] = "south-park"

    def test_depth_and_every_resource_budget_are_strictly_tiered(self) -> None:
        maximum, balanced, lightweight = variant.COMPILED_PROFILES
        fields = (
            "analysis_depth", "analysis_passes", "max_files",
            "max_file_bytes", "max_total_bytes", "max_findings",
            "max_graph_nodes", "max_worker_seconds",
            "max_worker_memory_bytes", "max_concurrency",
            "symbolic_timeout_seconds", "max_improvement_files",
            "max_worker_output_bytes", "max_ui_output_bytes",
            "validation_plan_limit",
        )
        for field in fields:
            with self.subTest(field=field):
                self.assertGreater(
                    getattr(maximum, field), getattr(balanced, field))
                self.assertGreater(
                    getattr(balanced, field), getattr(lightweight, field))

    def test_security_invariants_are_identical_and_cannot_be_profile_tuned(self) -> None:
        required_true = {
            "authorization_required_for_execution",
            "authorization_required_for_repairs",
            "authorization_scope_binding_required",
            "evidence_sha256_required",
            "fail_closed",
            "truth_guard_required",
        }
        required_false = {
            "network_access_default",
            "target_code_execution_default",
        }
        self.assertTrue(all(variant.SECURITY_INVARIANTS[key]
                            for key in required_true))
        self.assertTrue(all(not variant.SECURITY_INVARIANTS[key]
                            for key in required_false))
        policies = [
            variant.profile_dict(profile)["security_invariants"]
            for profile in variant.COMPILED_PROFILES
        ]
        self.assertEqual(policies[0], policies[1])
        self.assertEqual(policies[1], policies[2])

    def test_c3_response_language_is_canonical_and_maximum_only(self) -> None:
        maximum, balanced, lightweight = [
            variant.response_language_metadata(profile)
            for profile in variant.COMPILED_PROFILES
        ]
        self.assertEqual(maximum["tier"], "C3")
        self.assertEqual(
            maximum["label"], "C3 (Attestor-specific; not CEFR)")
        self.assertTrue(maximum["attestor_specific_tier"])
        self.assertFalse(maximum["official_cefr_claim"])
        for policy in (balanced, lightweight):
            self.assertEqual(policy["tier"], "existing")
            self.assertEqual(
                policy["renderer"], "response41-existing/4.1.3")
            self.assertFalse(policy["attestor_specific_tier"])
            self.assertFalse(policy["official_cefr_claim"])
        self.assertFalse(maximum["request_override_allowed"])

    def test_aliases_resolve_to_exact_canonical_singletons(self) -> None:
        cases = {
            "Cockroach Janta Party": variant.COCKROACH_JANTA_PARTY,
            "CJP": variant.COCKROACH_JANTA_PARTY,
            "MAX": variant.COCKROACH_JANTA_PARTY,
            "cockroach_janta.party": variant.COCKROACH_JANTA_PARTY,
            "South Park": variant.SOUTH_PARK,
            "SP": variant.SOUTH_PARK,
            "balanced": variant.SOUTH_PARK,
            " default ": variant.SOUTH_PARK,
            "Gruppe Sechs": variant.GRUPPE_SECHS,
            "GS": variant.GRUPPE_SECHS,
            "lightweight": variant.GRUPPE_SECHS,
            "low_resource": variant.GRUPPE_SECHS,
        }
        for alias, expected in cases.items():
            with self.subTest(alias=alias):
                self.assertIs(variant.parse_profile(alias), expected)
        for profile in variant.COMPILED_PROFILES:
            self.assertIs(variant.parse_profile(profile), profile)

    def test_api_slug_resolution_never_accepts_cli_aliases(self) -> None:
        for profile in variant.COMPILED_PROFILES:
            self.assertIs(variant.profile_for_slug(profile.slug), profile)
        for value in (
                "maximum", "balanced", "lightweight", "South Park",
                " south-park ", "SOUTH-PARK", variant.SOUTH_PARK, None):
            with self.subTest(value=repr(value)), self.assertRaises(
                    variant.VariantError):
                variant.profile_for_slug(value)

    def test_alias_parser_rejects_ambiguous_or_unbounded_values(self) -> None:
        invalid = (
            None, True, 1, b"south-park", "", " ", "x" * 129,
            "south\npark", "south/park", "Ｓｏｕｔｈ Park", "unknown",
        )
        for value in invalid:
            with self.subTest(value=repr(value)), self.assertRaises(
                    variant.VariantError):
                variant.parse_profile(value)

    def test_structurally_equal_and_mutated_clones_are_rejected(self) -> None:
        clone = replace(variant.SOUTH_PARK)
        self.assertEqual(clone, variant.SOUTH_PARK)
        self.assertIsNot(clone, variant.SOUTH_PARK)
        with self.assertRaisesRegex(variant.VariantError, "forged|canonical"):
            variant.require_compiled_profile(clone)
        object.__setattr__(clone, "max_files", clone.max_files + 1)
        with self.assertRaises(variant.VariantError):
            variant.require_compiled_profile(clone)
        with self.assertRaises(variant.VariantError):
            variant.profile_dict(clone)

    def test_constructor_boundaries_reject_bools_ranges_and_bad_relations(self) -> None:
        with self.assertRaises(variant.VariantError):
            replace(variant.SOUTH_PARK, max_files=True)
        with self.assertRaises(variant.VariantError):
            replace(variant.SOUTH_PARK, analysis_depth=0)
        with self.assertRaises(variant.VariantError):
            replace(variant.SOUTH_PARK, max_concurrency=33)
        with self.assertRaises(variant.VariantError):
            replace(variant.SOUTH_PARK, mode=["balanced"])
        with self.assertRaises(variant.VariantError):
            replace(
                variant.SOUTH_PARK,
                max_file_bytes=8 * variant.MIB,
                max_total_bytes=4 * variant.MIB)
        with self.assertRaises(variant.VariantError):
            replace(variant.SOUTH_PARK, slug="../escape")
        with self.assertRaises(variant.VariantError):
            replace(variant.SOUTH_PARK, legacy_components=[])
        with self.assertRaises(variant.VariantError):
            replace(variant.SOUTH_PARK, legacy_components=())
        with self.assertRaises(variant.VariantError):
            replace(
                variant.SOUTH_PARK,
                legacy_components=("scan", "scan"))
        with self.assertRaises(variant.VariantError):
            replace(
                variant.SOUTH_PARK,
                legacy_components=("scan", "uncompiled"))
        with self.assertRaises(variant.VariantError):
            replace(variant.SOUTH_PARK, worker_actions=())
        with self.assertRaises(variant.VariantError):
            replace(
                variant.SOUTH_PARK,
                worker_actions=("coding-static", "run-anything"))
        with self.assertRaises(variant.VariantError):
            replace(variant.SOUTH_PARK, symbolic_timeout_seconds=True)
        with self.assertRaises(variant.VariantError):
            replace(variant.SOUTH_PARK, max_worker_output_bytes=0)

    def test_exact_enforcement_policies_and_set_containment(self) -> None:
        maximum, balanced, lightweight = variant.COMPILED_PROFILES
        self.assertEqual(maximum.legacy_components, (
            "scan", "semantic", "security", "supply-chain", "symbolic",
            "polyglot-ir", "supply-chain-graph", "git-intelligence",
            "execution-fabric", "engineering", "security-fabric",
        ))
        self.assertEqual(balanced.legacy_components, (
            "scan", "semantic", "security", "supply-chain", "symbolic",
            "polyglot-ir", "supply-chain-graph", "engineering",
            "security-fabric",
        ))
        self.assertEqual(lightweight.legacy_components, (
            "scan", "semantic", "security", "supply-chain", "engineering",
            "security-fabric",
        ))
        self.assertEqual(maximum.worker_actions, (
            "coding-static", "security-static", "attack-static-413",
            "posture-static-413",
        ))
        self.assertEqual(balanced.worker_actions, maximum.worker_actions)
        self.assertEqual(
            lightweight.worker_actions,
            ("coding-static", "security-static"))
        self.assertLess(
            set(lightweight.legacy_components),
            set(balanced.legacy_components))
        self.assertLess(
            set(balanced.legacy_components),
            set(maximum.legacy_components))
        self.assertLess(
            set(lightweight.worker_actions),
            set(balanced.worker_actions))
        self.assertLessEqual(
            set(balanced.worker_actions),
            set(maximum.worker_actions))
        self.assertEqual(
            [
                (
                    profile.symbolic_timeout_seconds,
                    profile.max_improvement_files,
                    profile.max_worker_output_bytes,
                    profile.max_ui_output_bytes,
                    profile.validation_plan_limit,
                )
                for profile in variant.COMPILED_PROFILES
            ],
            [
                # CJP improvement files raised 12 -> 16, which is attestor41's own
                # hard maximum; anything above that is refused by the engine.
                (300, 16, 32 * variant.MIB, 32 * variant.MIB, 32),
                (120, 6, 16 * variant.MIB, 16 * variant.MIB, 16),
                (45, 2, 8 * variant.MIB, 8 * variant.MIB, 8),
            ])

    def test_generic_budgets_fit_hard_caps_and_resource_scope_is_explicit(self) -> None:
        self.assertEqual(
            {
                field: getattr(variant.COCKROACH_JANTA_PARTY, field)
                for field in variant.GENERIC_HARD_CEILINGS
            },
            dict(variant.GENERIC_HARD_CEILINGS))
        for profile in variant.COMPILED_PROFILES:
            for field, ceiling in variant.GENERIC_HARD_CEILINGS.items():
                with self.subTest(profile=profile.slug, field=field):
                    self.assertLessEqual(getattr(profile, field), ceiling)
        self.assertEqual(
            dict(variant.ENFORCEMENT_CONTRACT),
            {
                "coding_snapshot_and_graph_caps_only": True,
                "inherited_analyzer_caps_reported_separately": True,
                "inherited_analyzer_limit_hits_are_coverage_gaps": True,
                "resource_scope_is_stage_specific": True,
            })

    def test_profile_dictionaries_are_deterministic_fresh_and_identified(self) -> None:
        identities = []
        for profile in variant.COMPILED_PROFILES:
            one = variant.profile_dict(profile)
            two = variant.profile_dict(profile.slug)
            self.assertEqual(one, two)
            self.assertIsNot(one, two)
            self.assertTrue(variant.verify_profile_dict(one)[0])
            self.assertRegex(one["profile_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(
                variant.profile_identity(profile), one["profile_sha256"])
            self.assertEqual(
                one["response_language"],
                variant.response_language_metadata(profile))
            identities.append(one["profile_sha256"])
            one["resources"]["max_files"] = 1
            self.assertNotEqual(
                one["resources"]["max_files"],
                variant.profile_dict(profile)["resources"]["max_files"])
        self.assertEqual(len(set(identities)), 3)

    def test_serialized_profiles_load_only_to_canonical_singletons(self) -> None:
        for profile in variant.COMPILED_PROFILES:
            encoded = variant.profile_dict(profile)
            self.assertIs(variant.load_profile_dict(encoded), profile)
        forged = variant.profile_dict(variant.SOUTH_PARK)
        forged["resources"]["max_files"] += 1
        body = {key: value for key, value in forged.items()
                if key != "profile_sha256"}
        forged["profile_sha256"] = variant._sha(body)
        valid, errors = variant.verify_profile_dict(forged)
        self.assertFalse(valid)
        self.assertTrue(any("canonical" in error for error in errors))
        with self.assertRaises(variant.VariantError):
            variant.load_profile_dict(forged)

    def test_security_policy_forgery_fails_even_with_recomputed_digest(self) -> None:
        forged = variant.profile_dict(variant.GRUPPE_SECHS)
        forged["security_invariants"]["authorization_required_for_execution"] = False
        body = {key: value for key, value in forged.items()
                if key != "profile_sha256"}
        forged["profile_sha256"] = variant._sha(body)
        valid, errors = variant.verify_profile_dict(forged)
        self.assertFalse(valid)
        self.assertTrue(any("canonical" in error for error in errors))

    def test_component_and_worker_forgery_fails_with_recomputed_digest(self) -> None:
        for key, replacement in (
                ("legacy_components", ["scan"]),
                ("worker_actions", ["coding-static", "posture-static-413"])):
            forged = variant.profile_dict(variant.SOUTH_PARK)
            forged["analysis"][key] = replacement
            body = {name: value for name, value in forged.items()
                    if name != "profile_sha256"}
            forged["profile_sha256"] = variant._sha(body)
            valid, errors = variant.verify_profile_dict(forged)
            self.assertFalse(valid)
            self.assertTrue(any("canonical" in error for error in errors))

    def test_c3_forgery_fails_even_with_recomputed_profile_digest(self) -> None:
        forged = variant.profile_dict(variant.SOUTH_PARK)
        forged["response_language"] = variant.response_language_metadata(
            variant.COCKROACH_JANTA_PARTY)
        body = {
            name: value for name, value in forged.items()
            if name != "profile_sha256"
        }
        forged["profile_sha256"] = variant._sha(body)
        valid, errors = variant.verify_profile_dict(forged)
        self.assertFalse(valid)
        self.assertTrue(any("canonical" in error for error in errors))

    def test_selection_reports_are_alias_independent_and_verified(self) -> None:
        one = variant.selection_report(variant.parse_profile("balanced"))
        two = variant.selection_report("south-park")
        self.assertEqual(one, two)
        self.assertTrue(variant.verify_report(one)[0])
        self.assertEqual(
            one["selected_profile_sha256"],
            one["selected_profile"]["profile_sha256"])
        self.assertEqual(
            one["security_policy_sha256"], variant.SECURITY_POLICY_SHA256)
        self.assertEqual(
            one["enforcement_policy_sha256"],
            variant.ENFORCEMENT_POLICY_SHA256)
        self.assertRegex(one["report_sha256"], r"^[0-9a-f]{64}$")

    def test_report_tampering_extra_fields_and_rebinding_are_detected(self) -> None:
        original = variant.selection_report("cockroach-janta-party")
        mutations = []
        tampered = copy.deepcopy(original)
        tampered["selected_profile"]["resources"]["max_files"] -= 1
        mutations.append(tampered)
        tampered = copy.deepcopy(original)
        tampered["selected_profile_sha256"] = "0" * 64
        mutations.append(tampered)
        tampered = copy.deepcopy(original)
        tampered["security_policy_sha256"] = "0" * 64
        mutations.append(tampered)
        tampered = copy.deepcopy(original)
        tampered["enforcement_policy_sha256"] = "0" * 64
        mutations.append(tampered)
        tampered = copy.deepcopy(original)
        tampered["extra"] = True
        tampered["report_sha256"] = variant._sha({
            key: value for key, value in tampered.items()
            if key != "report_sha256"
        })
        mutations.append(tampered)
        for report in mutations:
            with self.subTest(keys=tuple(report)):
                valid, errors = variant.verify_report(report)
                self.assertFalse(valid)
                self.assertTrue(errors)

    def test_verifiers_fail_closed_on_hostile_shapes_without_throwing(self) -> None:
        hostile = [
            None,
            [],
            {"slug": "south-park", "padding": "x" * 20_000},
            {"slug": "south-park", 1: "non-text-key"},
            {"slug": "south-park", "float": float("nan")},
        ]
        cycle: dict[str, object] = {}
        cycle["cycle"] = cycle
        hostile.append(cycle)
        for value in hostile:
            with self.subTest(value_type=type(value).__name__):
                self.assertFalse(variant.verify_profile_dict(value)[0])
                self.assertFalse(variant.verify_report(value)[0])

    def test_public_identities_have_exact_sha256_shape(self) -> None:
        self.assertEqual(
            variant.ANALYZER_BUILD_SHA256,
            hashlib.sha256(
                (Path(__file__).resolve().parent / "detect.py").read_bytes()
            ).hexdigest(),
        )
        expected_profiles = {
            # Moved when CJP's file/total/finding budgets were raised to what
            # truth_guard41 actually accepts.  A profile edit is *supposed* to
            # change this digest: it is what binds a report to its exact policy.
            # Moved again when java-fixed-seed was added: every one of these
            # cascades from ANALYZER_BUILD_SHA256, so any change to detect.py
            # moves all six. That cascade is the point -- a report cannot stay
            # comparable across a rule engine it was not produced by.
            # Moved again when the Go/Rust/C# packs were added and those three
            # extensions stopped being `text`: twenty new rules and a changed
            # LANG_BY_EXT are new detector bytes, so every identity below is a
            # different analyzer's identity and says so.
            "cockroach-janta-party":
                "262e16abfdf436424b598b1cf5b78e58582f280587da4d82f2af3dc68468de00",
            "south-park":
                "1fbc48a77fab1c7ad52acfb4bca5ed9d031c7633d75341bdd421acf751b591a7",
            "gruppe-sechs":
                "7b25ea99bd9f118faf6ea6dd23798dc946946c1d7409ef07c8fbb6016a0c1150",
        }
        expected_reports = {
            # Follows the profile digest above: the selection report embeds the
            # profile, so raising CJP's budgets necessarily moves both.
            "cockroach-janta-party":
                "1da087e3ea127254fdfb71c977a2b4ee23ab582d00140eb0c4cb234c1a6e178d",
            "south-park":
                "196e7e50858c05d6d20b2d54932b1eb7cbba59cd4a908e3df12c77ff529645e2",
            "gruppe-sechs":
                "5958c5e0747c77b7a558602c42d0b6888b16e2bab106cb326aba7926a11bec11",
        }
        self.assertEqual(
            variant.SECURITY_POLICY_SHA256,
            "317a736d341b54d5f528080fe8a7efaf2fe9aadc3d808a39bf4c96d1f4e464ee")
        self.assertEqual(
            variant.ENFORCEMENT_POLICY_SHA256,
            "32946c875f1fc682ddc45d7df1b983b25155fc792de0d5cdc7268fe9b0f42591")
        self.assertEqual(
            {item.slug: variant.profile_identity(item)
             for item in variant.COMPILED_PROFILES},
            expected_profiles)
        self.assertEqual(
            {item.slug: variant.selection_report(item)["report_sha256"]
             for item in variant.COMPILED_PROFILES},
            expected_reports)
        self.assertFalse(
            re.search(r"[^0-9a-f]", variant.SECURITY_POLICY_SHA256))


if __name__ == "__main__":
    unittest.main()
