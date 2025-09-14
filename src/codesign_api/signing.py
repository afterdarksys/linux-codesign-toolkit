"""
Core signing functionality - wraps the existing bash-based toolkit.
Designed and Developed by: Ryan Coleman <coleman.ryan@gmail.com>
"""

import asyncio
import os
import hashlib
import shutil
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
import subprocess
import tempfile
import json
from datetime import datetime

from .config import settings
from .models import SigningType, OperationType
from .database import SigningOperation, AsyncSession

class SigningError(Exception):
    """Custom signing operation error."""
    pass

async def calculate_file_hash(file_path: str) -> str:
    """Calculate SHA-256 hash of a file."""
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

async def run_command(cmd: str, cwd: Optional[str] = None) -> Tuple[int, str, str]:
    """Run a shell command asynchronously."""
    process = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd
    )
    stdout, stderr = await process.communicate()
    return process.returncode, stdout.decode(), stderr.decode()

class CodeSigningEngine:
    """Core code signing engine that wraps the existing bash toolkit."""

    def __init__(self):
        self.toolkit_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "codesign-toolkit.sh")
        if not os.path.exists(self.toolkit_path):
            # Fallback to current directory
            self.toolkit_path = "./codesign-toolkit.sh"

    async def sign_file(
        self,
        operation: SigningOperation,
        signing_type: SigningType,
        input_file: str,
        output_file: str,
        key_id: str,
        timestamp_url: Optional[str] = None,
        **kwargs
    ) -> bool:
        """Sign a file using the appropriate signing method."""

        try:
            if signing_type == SigningType.WINDOWS:
                return await self._sign_windows(operation, input_file, output_file, key_id, timestamp_url, **kwargs)
            elif signing_type == SigningType.JAVA:
                return await self._sign_java(operation, input_file, output_file, key_id, timestamp_url, **kwargs)
            elif signing_type == SigningType.AIR:
                return await self._sign_air(operation, input_file, output_file, key_id, timestamp_url, **kwargs)
            elif signing_type == SigningType.APPLE:
                return await self._sign_apple(operation, input_file, output_file, key_id, timestamp_url, **kwargs)
            else:
                raise SigningError(f"Unsupported signing type: {signing_type}")

        except Exception as e:
            operation.error_message = str(e)
            raise SigningError(f"Signing failed: {str(e)}")

    async def verify_file(
        self,
        operation: SigningOperation,
        signing_type: SigningType,
        input_file: str,
        **kwargs
    ) -> bool:
        """Verify a signed file."""

        try:
            if signing_type == SigningType.WINDOWS:
                return await self._verify_windows(operation, input_file, **kwargs)
            elif signing_type == SigningType.JAVA:
                return await self._verify_java(operation, input_file, **kwargs)
            elif signing_type == SigningType.AIR:
                return await self._verify_air(operation, input_file, **kwargs)
            elif signing_type == SigningType.APPLE:
                return await self._verify_apple(operation, input_file, **kwargs)
            else:
                raise SigningError(f"Unsupported signing type: {signing_type}")

        except Exception as e:
            operation.error_message = str(e)
            raise SigningError(f"Verification failed: {str(e)}")

    async def unsign_file(
        self,
        operation: SigningOperation,
        input_file: str,
        output_file: str,
        **kwargs
    ) -> bool:
        """Remove signatures from a file."""

        try:
            # For now, only Windows files support unsigning
            return await self._unsign_windows(operation, input_file, output_file, **kwargs)

        except Exception as e:
            operation.error_message = str(e)
            raise SigningError(f"Unsigning failed: {str(e)}")

    async def _sign_windows(
        self,
        operation: SigningOperation,
        input_file: str,
        output_file: str,
        key_id: str,
        timestamp_url: Optional[str] = None,
        **kwargs
    ) -> bool:
        """Sign Windows binary using osslsigncode."""

        # Build command using the existing toolkit
        cmd_parts = [
            self.toolkit_path,
            "sign",
            "-type", "windows",
            "-in", input_file,
            "-out", output_file
        ]

        # Add certificate/key parameters based on key_id
        # This would need to be integrated with the certificate store
        cert_info = await self._get_certificate_info(key_id, SigningType.WINDOWS)
        if cert_info:
            if cert_info.get("cert_file"):
                cmd_parts.extend(["-cert", cert_info["cert_file"]])
            if cert_info.get("key_file"):
                cmd_parts.extend(["-key", cert_info["key_file"]])
            if cert_info.get("password"):
                cmd_parts.extend(["-pass", cert_info["password"]])

        # Add optional parameters
        if timestamp_url:
            cmd_parts.extend(["-timestamp", timestamp_url])

        app_name = kwargs.get("app_name")
        if app_name:
            cmd_parts.extend(["-name", app_name])

        app_url = kwargs.get("app_url")
        if app_url:
            cmd_parts.extend(["-url", app_url])

        cmd = " ".join(f'"{part}"' if " " in part else part for part in cmd_parts)
        returncode, stdout, stderr = await run_command(cmd)

        if returncode == 0:
            operation.metadata = json.dumps({
                "stdout": stdout,
                "stderr": stderr,
                "command": cmd
            })
            return True
        else:
            operation.error_message = f"Command failed with code {returncode}: {stderr}"
            return False

    async def _sign_java(
        self,
        operation: SigningOperation,
        input_file: str,
        output_file: str,
        key_id: str,
        timestamp_url: Optional[str] = None,
        **kwargs
    ) -> bool:
        """Sign Java JAR file using jarsigner."""

        cmd_parts = [
            self.toolkit_path,
            "sign",
            "-type", "java",
            "-in", input_file,
            "-out", output_file
        ]

        # Add keystore parameters
        cert_info = await self._get_certificate_info(key_id, SigningType.JAVA)
        if cert_info:
            if cert_info.get("keystore"):
                cmd_parts.extend(["-keystore", cert_info["keystore"]])
            if cert_info.get("alias"):
                cmd_parts.extend(["-alias", cert_info["alias"]])
            if cert_info.get("storepass"):
                cmd_parts.extend(["-storepass", cert_info["storepass"]])
            if cert_info.get("keypass"):
                cmd_parts.extend(["-keypass", cert_info["keypass"]])

        if timestamp_url:
            cmd_parts.extend(["-timestamp", timestamp_url])

        cmd = " ".join(f'"{part}"' if " " in part else part for part in cmd_parts)
        returncode, stdout, stderr = await run_command(cmd)

        if returncode == 0:
            operation.metadata = json.dumps({
                "stdout": stdout,
                "stderr": stderr,
                "command": cmd
            })
            return True
        else:
            operation.error_message = f"Command failed with code {returncode}: {stderr}"
            return False

    async def _sign_air(
        self,
        operation: SigningOperation,
        input_file: str,
        output_file: str,
        key_id: str,
        timestamp_url: Optional[str] = None,
        **kwargs
    ) -> bool:
        """Sign Adobe AIR file."""

        cmd_parts = [
            self.toolkit_path,
            "sign",
            "-type", "air",
            "-in", input_file,
            "-out", output_file
        ]

        cert_info = await self._get_certificate_info(key_id, SigningType.AIR)
        if cert_info:
            if cert_info.get("cert_file"):
                cmd_parts.extend(["-cert", cert_info["cert_file"]])
            if cert_info.get("password"):
                cmd_parts.extend(["-pass", cert_info["password"]])

        if timestamp_url:
            cmd_parts.extend(["-timestamp", timestamp_url])

        cmd = " ".join(f'"{part}"' if " " in part else part for part in cmd_parts)
        returncode, stdout, stderr = await run_command(cmd)

        if returncode == 0:
            operation.metadata = json.dumps({
                "stdout": stdout,
                "stderr": stderr,
                "command": cmd
            })
            return True
        else:
            operation.error_message = f"Command failed with code {returncode}: {stderr}"
            return False

    async def _sign_apple(
        self,
        operation: SigningOperation,
        input_file: str,
        output_file: str,
        key_id: str,
        timestamp_url: Optional[str] = None,
        **kwargs
    ) -> bool:
        """Sign Apple package/app."""

        cmd_parts = [
            self.toolkit_path,
            "sign",
            "-type", "apple",
            "-in", input_file,
            "-out", output_file
        ]

        cert_info = await self._get_certificate_info(key_id, SigningType.APPLE)
        if cert_info:
            if cert_info.get("cert_file"):
                cmd_parts.extend(["-cert", cert_info["cert_file"]])
            if cert_info.get("password"):
                cmd_parts.extend(["-pass", cert_info["password"]])

        if timestamp_url:
            cmd_parts.extend(["-timestamp", timestamp_url])

        cmd = " ".join(f'"{part}"' if " " in part else part for part in cmd_parts)
        returncode, stdout, stderr = await run_command(cmd)

        if returncode == 0:
            operation.metadata = json.dumps({
                "stdout": stdout,
                "stderr": stderr,
                "command": cmd
            })
            return True
        else:
            operation.error_message = f"Command failed with code {returncode}: {stderr}"
            return False

    async def _verify_windows(self, operation: SigningOperation, input_file: str, **kwargs) -> bool:
        """Verify Windows binary signature."""
        cmd = f'{self.toolkit_path} verify -in "{input_file}"'
        returncode, stdout, stderr = await run_command(cmd)

        operation.metadata = json.dumps({
            "stdout": stdout,
            "stderr": stderr,
            "command": cmd
        })

        return returncode == 0

    async def _verify_java(self, operation: SigningOperation, input_file: str, **kwargs) -> bool:
        """Verify Java JAR signature."""
        cmd = f'{self.toolkit_path} verify -in "{input_file}"'
        returncode, stdout, stderr = await run_command(cmd)

        operation.metadata = json.dumps({
            "stdout": stdout,
            "stderr": stderr,
            "command": cmd
        })

        return returncode == 0

    async def _verify_air(self, operation: SigningOperation, input_file: str, **kwargs) -> bool:
        """Verify Adobe AIR signature."""
        cmd = f'{self.toolkit_path} verify -in "{input_file}"'
        returncode, stdout, stderr = await run_command(cmd)

        operation.metadata = json.dumps({
            "stdout": stdout,
            "stderr": stderr,
            "command": cmd
        })

        return returncode == 0

    async def _verify_apple(self, operation: SigningOperation, input_file: str, **kwargs) -> bool:
        """Verify Apple package/app signature."""
        cmd = f'{self.toolkit_path} verify -in "{input_file}"'
        returncode, stdout, stderr = await run_command(cmd)

        operation.metadata = json.dumps({
            "stdout": stdout,
            "stderr": stderr,
            "command": cmd
        })

        return returncode == 0

    async def _unsign_windows(self, operation: SigningOperation, input_file: str, output_file: str, **kwargs) -> bool:
        """Remove Windows binary signature."""
        cmd = f'{self.toolkit_path} unsign -in "{input_file}" -out "{output_file}"'
        returncode, stdout, stderr = await run_command(cmd)

        operation.metadata = json.dumps({
            "stdout": stdout,
            "stderr": stderr,
            "command": cmd
        })

        return returncode == 0

    async def _get_certificate_info(self, key_id: str, signing_type: SigningType) -> Optional[Dict[str, str]]:
        """Get certificate information from the certificate store."""
        # This is a placeholder - in a real implementation, this would query
        # the CertificateStore table to get the actual certificate paths/data
        # For now, return None to use default behavior
        return None

# Global signing engine instance
signing_engine = CodeSigningEngine()