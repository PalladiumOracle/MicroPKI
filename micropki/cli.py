"""Command-line interface for MicroPKI."""

import argparse
import sys
import os
from pathlib import Path
from typing import Optional

from micropki.ca import RootCA
from micropki.crypto_utils import read_passphrase_file
from micropki import __version__


def validate_key_args(key_type: str, key_size: int) -> None:
    """
    Validate key type and size combination.
    
    Args:
        key_type: 'rsa' or 'ecc'.
        key_size: Key size in bits.
    
    Raises:
        ValueError: If combination is invalid.
    """
    if key_type == "rsa" and key_size != 4096:
        raise ValueError("RSA key size must be 4096 bits")
    elif key_type == "ecc" and key_size != 384:
        raise ValueError("ECC key size must be 384 bits (P-384 curve)")
    elif key_type not in ["rsa", "ecc"]:
        raise ValueError(f"Unsupported key type: {key_type}")


def validate_out_dir(out_dir: str) -> Path:
    """
    Validate and prepare output directory.
    
    Args:
        out_dir: Output directory path.
    
    Returns:
        Path object for the directory.
    
    Raises:
        ValueError: If directory exists but is not writable.
    """
    path = Path(out_dir)
    
    if path.exists():
        if not path.is_dir():
            raise ValueError(f"Output path exists and is not a directory: {out_dir}")
        if not os.access(path, os.W_OK):
            raise ValueError(f"Output directory is not writable: {out_dir}")
        
        # Check for potential file conflicts
        conflicts = []
        for f in ["private/ca.key.pem", "certs/ca.cert.pem", "policy.txt"]:
            if (path / f).exists():
                conflicts.append(f)
        
        if conflicts:
            # In a real implementation, we might prompt or require --force
            # For Sprint 1, we'll just warn
            print(f"Warning: The following files will be overwritten: {', '.join(conflicts)}", 
                  file=sys.stderr)
    else:
        # Check if parent directory is writable
        parent = path.parent
        if parent.exists() and not os.access(parent, os.W_OK):
            raise ValueError(f"Cannot create directory in: {parent}")
    
    return path


def validate_validity_days(days: int) -> None:
    """
    Validate validity days.
    
    Args:
        days: Number of days.
    
    Raises:
        ValueError: If days is not a positive integer.
    """
    if days <= 0:
        raise ValueError(f"Validity days must be positive, got: {days}")
    if days > 36500:  # 100 years sanity check
        raise ValueError(f"Validity days too large: {days}")


def ca_init(args: argparse.Namespace) -> int:
    """
    Handle the 'ca init' subcommand.
    
    Args:
        args: Parsed command-line arguments.
    
    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    try:
        # Validate subject
        if not args.subject:
            raise ValueError("Subject cannot be empty")
        
        # Validate key arguments
        validate_key_args(args.key_type, args.key_size)
        
        # Validate output directory
        out_path = validate_out_dir(args.out_dir)
        
        # Validate validity days
        validate_validity_days(args.validity_days)
        
        # Read passphrase file
        if not os.path.exists(args.passphrase_file):
            raise FileNotFoundError(f"Passphrase file not found: {args.passphrase_file}")
        if not os.access(args.passphrase_file, os.R_OK):
            raise PermissionError(f"Cannot read passphrase file: {args.passphrase_file}")
        
        passphrase = read_passphrase_file(args.passphrase_file)
        
        # Initialize CA
        ca = RootCA(out_dir=str(out_path), log_file=args.log_file)
        ca.initialize(
            subject_dn=args.subject,
            key_type=args.key_type,
            key_size=args.key_size,
            passphrase=passphrase,
            validity_days=args.validity_days
        )
        
        print(f"Root CA initialized successfully in {out_path}", file=sys.stdout)
        return 0
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def main() -> int:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="MicroPKI - A minimal Public Key Infrastructure implementation",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--version", 
        action="version", 
        version=f"MicroPKI v{__version__}"
    )
    
    subparsers = parser.add_subparsers(
        title="subcommands",
        dest="command",
        help="Available subcommands"
    )
    
    # 'ca init' subcommand
    ca_parser = subparsers.add_parser("ca", help="CA operations")
    ca_subparsers = ca_parser.add_subparsers(
        dest="ca_command",
        help="CA subcommands"
    )
    
    init_parser = ca_subparsers.add_parser("init", help="Initialize a new Root CA")
    
    # Required arguments
    init_parser.add_argument(
        "--subject",
        required=True,
        help="Distinguished Name (e.g., '/CN=My Root CA' or 'CN=My Root CA,O=Demo,C=US')"
    )
    init_parser.add_argument(
        "--passphrase-file",
        required=True,
        help="Path to file containing the passphrase for private key encryption"
    )
    
    # Optional arguments with defaults
    init_parser.add_argument(
        "--key-type",
        choices=["rsa", "ecc"],
        default="rsa",
        help="Key type: rsa or ecc (default: rsa)"
    )
    init_parser.add_argument(
        "--key-size",
        type=int,
        default=4096,
        help="Key size in bits: 4096 for RSA, 384 for ECC (default: 4096)"
    )
    init_parser.add_argument(
        "--out-dir",
        default="./pki",
        help="Output directory (default: ./pki)"
    )
    init_parser.add_argument(
        "--validity-days",
        type=int,
        default=3650,
        help="Validity period in days (default: 3650 ≈ 10 years)"
    )
    init_parser.add_argument(
        "--log-file",
        help="Optional path to log file (logs to stderr if omitted)"
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Handle subcommands
    if args.command == "ca":
        if args.ca_command == "init":
            return ca_init(args)
        else:
            print("Error: Missing CA subcommand. Use 'ca init'", file=sys.stderr)
            return 1
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
