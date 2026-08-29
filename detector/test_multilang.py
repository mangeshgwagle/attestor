import unittest

import multilang


class MultilangTests(unittest.TestCase):
    def rules(self, source, path):
        return {finding.rule for finding in multilang.analyze(source, path)}

    def test_rust_and_go_security_boundaries(self):
        self.assertIn("rust-transmute", self.rules("let x = transmute(y);", "lib.rs"))
        self.assertIn("go-insecure-tls", self.rules("InsecureSkipVerify: true", "main.go"))

    def test_java_and_csharp_unsafe_deserialization(self):
        self.assertIn("java-insecure-deserialization", self.rules("new ObjectInputStream(in);", "A.java"))
        self.assertIn("csharp-binaryformatter", self.rules("var f = new BinaryFormatter();", "A.cs"))

    def test_infrastructure_rules(self):
        self.assertIn("tf-public-ingress", self.rules('cidr_blocks = ["0.0.0.0/0"]', "main.tf"))
        self.assertIn("k8s-privileged", self.rules("securityContext:\n  privileged: true", "pod.yaml"))

    def test_dockerfile_rules_and_nonroot_suppression(self):
        rules = self.rules("FROM python:latest\nRUN echo ok\n", "Dockerfile")
        self.assertIn("docker-latest-tag", rules)
        self.assertIn("docker-root-default", rules)
        self.assertNotIn("docker-root-default", self.rules("FROM python:3.12\nUSER app\n", "Dockerfile"))

    def test_comments_are_not_reported(self):
        self.assertEqual(self.rules("// ObjectInputStream example", "A.java"), set())


if __name__ == "__main__":
    unittest.main()
