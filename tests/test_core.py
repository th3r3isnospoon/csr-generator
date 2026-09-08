import json
import os
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from csr_generator.crypto import create_artifacts, generate, load_key, public_bytes
from csr_generator.errors import ApplicationError, Cancelled, ValidationError
from csr_generator.models import ALGORITHMS, Request, Subject
from csr_generator.pem import bundle, inspect_pem, pem_blocks
from csr_generator.profiles import load_profile, profile_bytes
from csr_generator.storage import publish, save_exclusive
from csr_generator.validation import dns_name, validate_request


def request(**changes):
    base = Request(
        Subject(
            "example.test",
            "US",
            "Massachusetts",
            "Boston",
            "Example, Inc.",
            "Engineering",
            "admin@example.test",
        ),
        dns_names=("example.test", "*.example.test"),
        ip_addresses=("192.0.2.1", "2001:db8::1"),
        passphrase="  exact ' $ secret  ",
        self_signed=True,
    )
    return replace(base, **changes)


class ValidationTests(unittest.TestCase):
    def test_normalizes_and_deduplicates_sans(self):
        result = validate_request(
            request(
                dns_names=("BÜCHER.example", "xn--bcher-kva.example"),
                ip_addresses=("2001:0db8::1", "2001:db8::1"),
            )
        )
        self.assertEqual(result.dns_names, ("xn--bcher-kva.example",))
        self.assertEqual(result.ip_addresses, ("2001:db8::1",))

    def test_wildcard_and_single_trailing_dot(self):
        self.assertEqual(dns_name("*.BÜCHER.example."), "*.xn--bcher-kva.example")
        self.assertEqual(dns_name("EXAMPLE.test."), "example.test")

    def test_invalid_names(self):
        for value in (
            "bad name",
            "a.*.example",
            "*.*.example",
            "*.com",
            "a..test",
            "example.test..",
            "-a.test",
            "$(touch hacked)",
            "a\nDNS.2=bad.test",
            "192.0.2.1",
        ):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                dns_name(value)

    def test_invalid_inputs(self):
        cases = [
            dict(ip_addresses=("999.999.999.999",)),
            dict(ip_addresses=("fe80::1%eth0",)),
            dict(subject=Subject("test", country="USA")),
            dict(subject=Subject("test\nOU=bad")),
            dict(subject=Subject("test", email="invalid")),
            dict(algorithm="invalid"),
            dict(digest="sha1"),
            dict(algorithm="ed25519", digest="sha256"),
            dict(dns_names=(), ip_addresses=()),
            dict(validity_days=0),
            dict(validity_days=True),
            dict(passphrase=""),
            dict(encrypt_key=False),
            dict(passphrase="a\npassword"),
        ]
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                validate_request(request(**changes))

    def test_generic_allows_no_sans_or_email(self):
        result = create_artifacts(
            request(
                profile="generic",
                dns_names=(),
                ip_addresses=(),
                subject=Subject("Not a DNS identity"),
            )
        )
        csr = x509.load_pem_x509_csr(result.csr)
        self.assertEqual(len(csr.extensions), 0)


class CryptoTests(unittest.TestCase):
    def test_every_algorithm_subject_sans_encryption_and_certificate(self):
        for algorithm in ALGORITHMS:
            with self.subTest(algorithm=algorithm):
                req = request(algorithm=algorithm)
                result = create_artifacts(req)
                self.assertIn(b"ENCRYPTED PRIVATE KEY", result.key)
                with self.assertRaises(ValueError):
                    serialization.load_pem_private_key(result.key, b"wrong")
                key = load_key(result.key, req.passphrase)
                csr = x509.load_pem_x509_csr(result.csr)
                self.assertTrue(csr.is_signature_valid)
                self.assertEqual(
                    csr.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value,
                    "Example, Inc.",
                )
                self.assertEqual(len(csr.subject), 7)
                self.assertEqual(
                    len(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value),
                    4,
                )
                cert = x509.load_pem_x509_certificate(result.certificate)
                cert.verify_directly_issued_by(cert)
                self.assertEqual(cert.subject, csr.subject)
                self.assertEqual(public_bytes(cert.public_key()), public_bytes(key.public_key()))
                self.assertFalse(
                    cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                )
                self.assertIn(
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value,
                )
                self.assertGreater(
                    cert.not_valid_after_utc, datetime.now(UTC) + timedelta(days=364)
                )

    def test_digest_applies_to_csr_and_cert(self):
        result = create_artifacts(request(digest="sha512"))
        self.assertEqual(x509.load_pem_x509_csr(result.csr).signature_hash_algorithm.name, "sha512")
        self.assertEqual(
            x509.load_pem_x509_certificate(result.certificate).signature_hash_algorithm.name,
            "sha512",
        )

    def test_existing_key_reuses_identity_and_reencrypts(self):
        original = create_artifacts(request(algorithm="rsa-2048"))
        renewal = create_artifacts(
            request(
                existing_key=original.key,
                existing_passphrase=request().passphrase,
                passphrase="new password",
            )
        )
        self.assertEqual(
            public_bytes(load_key(original.key, request().passphrase).public_key()),
            public_bytes(load_key(renewal.key, "new password").public_key()),
        )
        with self.assertRaises(ValidationError):
            load_key(renewal.key, request().passphrase)

    def test_explicit_unencrypted_key(self):
        result = create_artifacts(request(encrypt_key=False, passphrase=""))
        self.assertNotIn(b"ENCRYPTED", result.key)
        load_key(result.key)

    def test_cancellation_before_work(self):
        with patch("csr_generator.crypto.make_key") as make, self.assertRaises(Cancelled):
            create_artifacts(request(), lambda: True)
        make.assert_not_called()

    def test_secret_not_in_repr(self):
        self.assertNotIn(request().passphrase, repr(request()))
        self.assertNotIn("PRIVATE KEY", repr(create_artifacts(request())))


class StorageTests(unittest.TestCase):
    def test_paths_never_contain_cn_and_never_collide(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "spaces and ' quotes ü"
            req = request(subject=Subject("../../absolute;$(echo nope)"))
            first, second = generate(req, root), generate(req, root)
            self.assertNotEqual(first.directory, second.directory)
            self.assertEqual(first.directory.parent, root.resolve())
            self.assertEqual(
                {p.name for p in first.files}, {"private-key.pem", "request.csr", "certificate.crt"}
            )
            if os.name == "posix":
                self.assertEqual(first.directory.stat().st_mode & 0o777, 0o700)
                for path in first.files:
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_exclusive_export_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "private.pem"
            save_exclusive(path, b"original")
            with self.assertRaises(ApplicationError):
                save_exclusive(path, b"replacement")
            self.assertEqual(path.read_bytes(), b"original")
            if os.name == "posix":
                link = Path(tmp) / "link.pem"
                link.symlink_to(path)
                with self.assertRaises(ApplicationError):
                    save_exclusive(link, b"replacement")
                self.assertEqual(path.read_bytes(), b"original")

    def test_failure_cleans_partial_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch(
                "csr_generator.storage.save_exclusive", side_effect=ApplicationError("disk full")
            ):
                with self.assertRaises(ApplicationError):
                    publish(create_artifacts(request()), Path(tmp))
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_permission_failure_saves_no_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "key.pem"
            with patch(
                "csr_generator.storage.restrict_windows", side_effect=ApplicationError("ACL failed")
            ):
                with self.assertRaises(ApplicationError):
                    save_exclusive(path, b"SECRET")
            self.assertFalse(path.exists())

    def test_cancel_cleans_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            checks = iter((False, False, True))
            with self.assertRaises(Cancelled):
                publish(create_artifacts(request()), Path(tmp), lambda: next(checks))
            self.assertEqual(list(Path(tmp).iterdir()), [])


class PemTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = create_artifacts(request())

    def test_empty_and_junk_rejected(self):
        for value in (
            b"",
            b"\n",
            b"junk",
            b"junk\n" + self.artifacts.certificate,
            self.artifacts.certificate + b"trailing",
        ):
            with self.subTest(value=value[:20]), self.assertRaises(ValidationError):
                bundle(value)

    def test_key_match_encryption_preservation_and_pkcs12(self):
        result = bundle(
            self.artifacts.certificate, self.artifacts.key, request().passphrase, mode="combined"
        )
        self.assertEqual(
            [label for label, _ in pem_blocks(result)], ["CERTIFICATE", "ENCRYPTED PRIVATE KEY"]
        )
        p12 = bundle(
            self.artifacts.certificate,
            self.artifacts.key,
            request().passphrase,
            mode="pkcs12",
            export_passphrase="export secret",
        )
        key, cert, _ = pkcs12.load_key_and_certificates(p12, b"export secret")
        self.assertEqual(public_bytes(key.public_key()), public_bytes(cert.public_key()))
        with self.assertRaises(ValueError):
            pkcs12.load_key_and_certificates(p12, b"wrong")

    def test_mismatch_and_duplicates_rejected(self):
        other = create_artifacts(request())
        with self.assertRaises(ValidationError):
            bundle(self.artifacts.certificate, other.key, request().passphrase, mode="combined")
        with self.assertRaises(ValidationError):
            bundle(self.artifacts.certificate * 2)

    def test_inspection_and_signature_failure(self):
        self.assertIn("self-signature: valid", inspect_pem(self.artifacts.csr, "csr"))
        self.assertIn("not performed", inspect_pem(self.artifacts.certificate, "certificate"))
        csr = x509.load_pem_x509_csr(self.artifacts.csr)
        der = bytearray(csr.public_bytes(serialization.Encoding.DER))
        der[-1] ^= 1
        bad = x509.load_der_x509_csr(bytes(der)).public_bytes(serialization.Encoding.PEM)
        with self.assertRaises(ValidationError):
            inspect_pem(bad, "csr")

    def test_real_chain_order_and_root_omission(self):
        now = datetime.now(UTC)
        root_key = ec.generate_private_key(ec.SECP256R1())
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test root")])
        root = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(root_key.public_key())
            .serial_number(1)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(True, None), True)
            .sign(root_key, hashes.SHA256())
        )
        leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]))
            .issuer_name(name)
            .public_key(leaf_key.public_key())
            .serial_number(2)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=1))
            .sign(root_key, hashes.SHA256())
        )
        chain = leaf.public_bytes(serialization.Encoding.PEM) + root.public_bytes(
            serialization.Encoding.PEM
        )
        self.assertEqual(len(pem_blocks(bundle(chain))), 1)
        self.assertEqual(len(pem_blocks(bundle(chain, include_root=True))), 2)
        with self.assertRaises(ValidationError):
            bundle(
                root.public_bytes(serialization.Encoding.PEM)
                + leaf.public_bytes(serialization.Encoding.PEM)
            )


class ProfileTests(unittest.TestCase):
    def test_roundtrip_excludes_secrets(self):
        data = profile_bytes(
            request(existing_key=b"SECRET KEY", existing_passphrase="INPUT SECRET")
        )
        for secret in (
            request().passphrase.encode(),
            b"SECRET KEY",
            b"INPUT SECRET",
            b"passphrase",
        ):
            self.assertNotIn(secret, data)
        loaded = load_profile(data)
        self.assertEqual(loaded.subject, request().subject)
        self.assertTrue(loaded.encrypt_key)
        self.assertEqual(loaded.passphrase, "")

    def test_rejects_secret_in_profile(self):
        data = json.loads(profile_bytes(request()))
        data["request"]["passphrase"] = "bad idea"
        with self.assertRaises(ValidationError):
            load_profile(json.dumps(data).encode())


if __name__ == "__main__":
    unittest.main()
