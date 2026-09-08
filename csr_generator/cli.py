"""Headless interface. Passwords are prompted, never accepted as command arguments."""

import argparse
import getpass
import sys
from pathlib import Path

from . import __version__
from .crypto import generate
from .errors import ApplicationError
from .io import read_input
from .models import ALGORITHMS, DIGESTS, PROFILES, Request, Subject
from .pem import bundle, inspect_pem
from .profiles import load_profile
from .storage import save_exclusive


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Local CSR and certificate tools")
    result.add_argument("--version", action="version", version=__version__)
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("gui", help="Launch the desktop application")
    gen = commands.add_parser("generate", help="Generate a key and CSR")
    gen.add_argument("--profile-file", type=Path)
    gen.add_argument("--cn")
    for field in ("country", "state", "locality", "organization", "organizational-unit", "email"):
        gen.add_argument("--" + field, default=None)
    gen.add_argument("--dns", action="append", default=None)
    gen.add_argument("--ip", action="append", default=None)
    gen.add_argument("--algorithm", choices=ALGORITHMS)
    gen.add_argument("--digest", choices=DIGESTS)
    gen.add_argument("--profile", choices=PROFILES)
    gen.add_argument("--self-signed", action="store_true", default=None)
    gen.add_argument("--days", type=int)
    gen.add_argument(
        "--unencrypted", action="store_true", help="Explicitly save an unencrypted key"
    )
    gen.add_argument("--existing-key", type=Path)
    gen.add_argument("--existing-key-encrypted", action="store_true")
    gen.add_argument("--output", type=Path, required=True)
    inspect = commands.add_parser("inspect", help="Inspect CSR/certificate PEM")
    inspect.add_argument("kind", choices=["csr", "certificate"])
    inspect.add_argument("input", type=Path)
    inspect.add_argument("--openssl", action="store_true", help="Also include OpenSSL text")
    export = commands.add_parser("bundle", help="Validate and export PEM or PKCS#12")
    export.add_argument("--certificates", type=Path)
    export.add_argument("--key", type=Path)
    export.add_argument("--key-encrypted", action="store_true")
    export.add_argument("--mode", choices=["chain", "key", "combined", "pkcs12"], default="chain")
    export.add_argument("--include-root", action="store_true")
    export.add_argument("--output", type=Path, required=True)
    return result


def new_password() -> str:
    first = getpass.getpass("Output key/bundle passphrase: ")
    if first != getpass.getpass("Confirm passphrase: "):
        raise ApplicationError("Passphrases do not match.")
    return first


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "gui":
            from .gui import main as gui_main

            gui_main()
        elif args.command == "inspect":
            data = read_input(args.input)
            print(inspect_pem(data, args.kind))
            if args.openssl:
                from .openssl import OpenSSL

                backend = OpenSSL()
                print(backend.version())
                print(backend.decode(data, args.kind))
        elif args.command == "bundle":
            data = bundle(
                read_input(args.certificates) if args.certificates else b"",
                read_input(args.key) if args.key else b"",
                getpass.getpass("Input key passphrase: ") if args.key_encrypted else "",
                args.mode,
                args.include_root,
                export_passphrase=new_password() if args.mode == "pkcs12" else "",
            )
            print(save_exclusive(args.output, data))
        else:
            from dataclasses import replace

            base = (
                load_profile(read_input(args.profile_file))
                if args.profile_file
                else Request(Subject(""))
            )
            subject = {
                name: getattr(args, name)
                for name in Subject.__dataclass_fields__
                if name != "common_name" and getattr(args, name) is not None
            }
            if args.cn is not None:
                subject["common_name"] = args.cn
            changes = {
                name: getattr(args, name)
                for name in ("algorithm", "digest", "profile", "self_signed")
                if getattr(args, name) is not None
            }
            if args.dns is not None:
                changes["dns_names"] = tuple(args.dns)
            if args.ip is not None:
                changes["ip_addresses"] = tuple(args.ip)
            if args.days is not None:
                changes["validity_days"] = args.days
            request = replace(
                base,
                subject=replace(base.subject, **subject),
                **changes,
                encrypt_key=not args.unencrypted,
                passphrase="" if args.unencrypted else new_password(),
                existing_key=read_input(args.existing_key) if args.existing_key else None,
                existing_passphrase=(
                    getpass.getpass("Input key passphrase: ") if args.existing_key_encrypted else ""
                ),
            )
            result = generate(request, args.output)
            print("Created:")
            for path in result.files:
                print(path)
        return 0
    except (ApplicationError, KeyboardInterrupt, EOFError) as exc:
        print(str(exc) or "Cancelled.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
