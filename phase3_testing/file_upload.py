#!/usr/bin/env python3
"""
File Upload vulnerability testing module.

Usage:
    python file_upload.py --target https://example.com/upload --output results/
"""

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.http_client import AsyncHTTPClient, HTTPResponse
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, normalize_url, extract_domain, timestamp_now, ensure_dir

logger = setup_logging("file_upload")


@dataclass
class FileUploadVuln:
    """Represents a file upload vulnerability."""

    url: str
    vuln_type: str
    description: str
    evidence: str
    filename: str = ""
    content_type: str = ""
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "vuln_type": self.vuln_type,
            "description": self.description,
            "evidence": self.evidence[:500] if self.evidence else "",
            "filename": self.filename,
            "content_type": self.content_type,
            "confidence": self.confidence,
        }


class FileUploadTester:
    """
    File Upload vulnerability tester.

    Features:
    - Extension bypass testing
    - Content-type bypass testing
    - Double extension attacks
    - Null byte injection
    - Polyglot file uploads
    - Path traversal in filename
    - SVG XSS testing
    """

    # Test file content
    PHP_WEBSHELL = '<?php echo "VULN_MARKER_" . md5("test") . "_MARKER"; ?>'
    JSP_WEBSHELL = '<%= "VULN_MARKER_" + "test".hashCode() + "_MARKER" %>'
    ASP_WEBSHELL = '<% Response.Write("VULN_MARKER_test_MARKER") %>'
    HTML_XSS = '<html><body><script>document.write("VULN_MARKER_XSS_MARKER")</script></body></html>'
    SVG_XSS = '''<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg">
<script type="text/javascript">alert('VULN_MARKER_SVG_MARKER')</script>
</svg>'''

    # Minimal GIF header + PHP
    GIF_PHP = b'GIF89a<?php echo "VULN_MARKER_GIF_MARKER"; ?>'

    # Minimal PNG header + PHP
    PNG_PHP = b'\x89PNG\r\n\x1a\n<?php echo "VULN_MARKER_PNG_MARKER"; ?>'

    DANGEROUS_EXTENSIONS = [
        # PHP
        ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar",
        ".phps", ".pht", ".phpt", ".pgif", ".phtm",
        # ASP/ASPX
        ".asp", ".aspx", ".cer", ".asa", ".ashx", ".asmx", ".axd",
        # JSP
        ".jsp", ".jspx", ".jsw", ".jsv", ".jspf",
        # Other
        ".exe", ".sh", ".bat", ".cmd", ".ps1", ".py", ".pl", ".cgi",
        ".htaccess", ".config", ".shtml",
    ]

    EXTENSION_BYPASSES = [
        # Case variations
        (".PHP", "case_upper"),
        (".Php", "case_mixed"),
        (".pHp", "case_mixed2"),
        # Double extensions
        (".php.jpg", "double_ext"),
        (".php.png", "double_ext"),
        (".jpg.php", "double_ext_reverse"),
        # Null byte
        (".php%00.jpg", "null_byte_url"),
        (".php\x00.jpg", "null_byte_raw"),
        # Special characters
        (".php.", "trailing_dot"),
        (".php ", "trailing_space"),
        (".php::$DATA", "ntfs_ads"),
        # Less common
        (".php;.jpg", "semicolon"),
        (".php%0a.jpg", "newline"),
        (".php%0d.jpg", "carriage_return"),
    ]

    CONTENT_TYPE_BYPASSES = [
        ("image/jpeg", "image_jpeg"),
        ("image/png", "image_png"),
        ("image/gif", "image_gif"),
        ("application/octet-stream", "octet_stream"),
        ("text/plain", "text_plain"),
        ("application/x-httpd-php", "php_content_type"),
    ]

    PATH_TRAVERSAL_FILENAMES = [
        "../../../tmp/test.php",
        "..\\..\\..\\tmp\\test.php",
        "....//....//....//tmp/test.php",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2ftmp/test.php",
        "..%252f..%252f..%252ftmp/test.php",
    ]

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
        file_field: str = "file",
        auth_cookie: Optional[str] = None,
        verbose: bool = False,
    ):
        self.target = normalize_url(target)
        self.target_domain = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.file_field = file_field
        self.auth_cookie = auth_cookie
        self.verbose = verbose

        self.vulnerabilities: List[FileUploadVuln] = []
        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

        self.uploaded_files: List[Dict] = []

    async def test(self) -> ScanResult:
        """Run file upload tests."""
        result = ScanResult(
            tool="file_upload",
            target=self.target,
            config={"timeout": self.timeout},
        )

        logger.info(f"Starting file upload testing for: {self.target}")

        try:
            # Test dangerous extension uploads
            await self._test_dangerous_extensions()

            # Test extension bypass techniques
            await self._test_extension_bypasses()

            # Test content-type bypass
            await self._test_content_type_bypass()

            # Test polyglot files
            await self._test_polyglot_files()

            # Test SVG XSS
            await self._test_svg_xss()

            # Test path traversal in filename
            await self._test_path_traversal()

            result.stats = {
                "vulnerabilities_found": len(self.vulnerabilities),
                "files_uploaded": len(self.uploaded_files),
            }

            for vuln in self.vulnerabilities:
                severity_map = {
                    "critical": Severity.CRITICAL,
                    "high": Severity.HIGH,
                    "medium": Severity.MEDIUM,
                    "low": Severity.LOW,
                }
                severity = severity_map.get(vuln.confidence, Severity.HIGH)

                result.add_finding(Finding(
                    title=f"File Upload: {vuln.vuln_type}",
                    severity=severity,
                    description=vuln.description,
                    url=vuln.url,
                    evidence=vuln.evidence,
                    metadata={
                        "filename": vuln.filename,
                        "content_type": vuln.content_type,
                    },
                    cwe_id="CWE-434",
                    remediation="Implement strict file validation: check extensions, content-type, and file content. Store uploads outside webroot.",
                ))

        except Exception as e:
            result.add_error(f"Testing error: {e}")
            logger.error(f"Testing error: {e}")

        result.finalize()
        return result

    async def _upload_file(
        self,
        filename: str,
        content: bytes,
        content_type: str = "application/octet-stream",
    ) -> Optional[HTTPResponse]:
        """Upload a file and return response."""
        headers = {}
        if self.auth_cookie:
            headers["Cookie"] = self.auth_cookie

        async with AsyncHTTPClient(timeout=self.timeout, proxy=self.proxy) as client:
            try:
                # Escape filename for Content-Disposition header
                # Replace quotes and newlines that could break the header
                safe_filename = filename.replace('"', '\\"').replace('\n', '').replace('\r', '')

                # Build multipart form data manually
                boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
                body = (
                    f'--{boundary}\r\n'
                    f'Content-Disposition: form-data; name="{self.file_field}"; filename="{safe_filename}"\r\n'
                    f'Content-Type: {content_type}\r\n\r\n'
                ).encode() + content + f'\r\n--{boundary}--\r\n'.encode()

                headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"

                response = await client.post(
                    self.target,
                    headers=headers,
                    data=body,
                )

                return response

            except Exception as e:
                logger.debug(f"Upload error: {e}")
                return None

    def _check_upload_success(self, response: HTTPResponse, marker: str = "VULN_MARKER") -> bool:
        """Check if upload was successful and potentially executable."""
        if response.status not in [200, 201, 302]:
            return False

        body_lower = response.body.lower()

        # Check for explicit error indicators first (higher priority)
        error_indicators = [
            "error",
            "invalid",
            "denied",
            "forbidden",
            "not allowed",
            "rejected",
            "failed",
            "unsupported",
            "blocked",
            "disallowed",
            "extension not permitted",
            "file type not allowed",
        ]

        # If any error indicator is present, consider it a failure
        if any(ind in body_lower for ind in error_indicators):
            return False

        # Check for success indicators
        success_indicators = [
            "upload successful",
            "uploaded successfully",
            "file saved",
            "file stored",
            "successfully uploaded",
            marker.lower(),
            '"success":true',
            '"success": true',
            '"status":"ok"',
            '"status": "ok"',
        ]

        # Also check for file URL/path in response (common indicator of success)
        file_path_indicators = [
            "/uploads/",
            "/files/",
            "/media/",
            "file_url",
            "file_path",
            "download_url",
        ]

        has_success = any(ind in body_lower for ind in success_indicators)
        has_file_path = any(ind in body_lower for ind in file_path_indicators)

        return has_success or has_file_path

    async def _test_dangerous_extensions(self):
        """Test upload of dangerous file extensions."""
        logger.info("Testing dangerous extensions...")

        for ext in self.DANGEROUS_EXTENSIONS[:5]:  # Test subset for speed
            filename = f"test{ext}"

            if ext.startswith(".php"):
                content = self.PHP_WEBSHELL.encode()
            elif ext.startswith(".jsp"):
                content = self.JSP_WEBSHELL.encode()
            elif ext.startswith(".asp"):
                content = self.ASP_WEBSHELL.encode()
            else:
                content = b"test content"

            response = await self._upload_file(filename, content)

            if response and self._check_upload_success(response):
                vuln = FileUploadVuln(
                    url=self.target,
                    vuln_type="dangerous_extension",
                    description=f"Dangerous file extension accepted: {ext}",
                    evidence=response.body[:200],
                    filename=filename,
                    content_type="application/octet-stream",
                    confidence="high" if ext in [".php", ".jsp", ".asp"] else "medium",
                )
                self.vulnerabilities.append(vuln)
                self.uploaded_files.append({"filename": filename, "type": "dangerous_ext"})
                logger.info(f"Dangerous extension accepted: {ext}")

    async def _test_extension_bypasses(self):
        """Test extension bypass techniques."""
        logger.info("Testing extension bypasses...")

        for ext_bypass, bypass_type in self.EXTENSION_BYPASSES:
            filename = f"test{ext_bypass}"
            content = self.PHP_WEBSHELL.encode()

            response = await self._upload_file(filename, content)

            if response and self._check_upload_success(response):
                vuln = FileUploadVuln(
                    url=self.target,
                    vuln_type=f"extension_bypass_{bypass_type}",
                    description=f"Extension bypass successful: {ext_bypass}",
                    evidence=response.body[:200],
                    filename=filename,
                    content_type="application/octet-stream",
                    confidence="high",
                )
                self.vulnerabilities.append(vuln)
                self.uploaded_files.append({"filename": filename, "type": bypass_type})
                logger.info(f"Extension bypass successful: {bypass_type}")

    async def _test_content_type_bypass(self):
        """Test content-type bypass."""
        logger.info("Testing content-type bypass...")

        for content_type, bypass_type in self.CONTENT_TYPE_BYPASSES:
            filename = "test.php"
            content = self.PHP_WEBSHELL.encode()

            response = await self._upload_file(filename, content, content_type)

            if response and self._check_upload_success(response):
                vuln = FileUploadVuln(
                    url=self.target,
                    vuln_type=f"content_type_bypass_{bypass_type}",
                    description=f"Content-Type bypass: PHP uploaded as {content_type}",
                    evidence=response.body[:200],
                    filename=filename,
                    content_type=content_type,
                    confidence="high",
                )
                self.vulnerabilities.append(vuln)
                self.uploaded_files.append({"filename": filename, "type": bypass_type})
                logger.info(f"Content-type bypass successful: {bypass_type}")
                return  # One success is enough

    async def _test_polyglot_files(self):
        """Test polyglot file uploads (valid image + PHP)."""
        logger.info("Testing polyglot files...")

        polyglots = [
            ("test.gif.php", self.GIF_PHP, "image/gif"),
            ("test.png.php", self.PNG_PHP, "image/png"),
        ]

        for filename, content, content_type in polyglots:
            response = await self._upload_file(filename, content, content_type)

            if response and self._check_upload_success(response):
                vuln = FileUploadVuln(
                    url=self.target,
                    vuln_type="polyglot_upload",
                    description=f"Polyglot file accepted: {filename}",
                    evidence=response.body[:200],
                    filename=filename,
                    content_type=content_type,
                    confidence="high",
                )
                self.vulnerabilities.append(vuln)
                self.uploaded_files.append({"filename": filename, "type": "polyglot"})
                logger.info(f"Polyglot upload successful: {filename}")

    async def _test_svg_xss(self):
        """Test SVG XSS upload."""
        logger.info("Testing SVG XSS...")

        filename = "test.svg"
        content = self.SVG_XSS.encode()

        response = await self._upload_file(filename, content, "image/svg+xml")

        if response and self._check_upload_success(response):
            vuln = FileUploadVuln(
                url=self.target,
                vuln_type="svg_xss",
                description="SVG file with XSS payload accepted",
                evidence=response.body[:200],
                filename=filename,
                content_type="image/svg+xml",
                confidence="medium",
            )
            self.vulnerabilities.append(vuln)
            self.uploaded_files.append({"filename": filename, "type": "svg_xss"})
            logger.info("SVG XSS upload successful")

    async def _test_path_traversal(self):
        """Test path traversal in filename."""
        logger.info("Testing path traversal in filename...")

        for filename in self.PATH_TRAVERSAL_FILENAMES:
            content = self.PHP_WEBSHELL.encode()

            response = await self._upload_file(filename, content)

            if response and self._check_upload_success(response):
                vuln = FileUploadVuln(
                    url=self.target,
                    vuln_type="path_traversal",
                    description=f"Path traversal in filename accepted: {filename}",
                    evidence=response.body[:200],
                    filename=filename,
                    content_type="application/octet-stream",
                    confidence="critical",
                )
                self.vulnerabilities.append(vuln)
                self.uploaded_files.append({"filename": filename, "type": "path_traversal"})
                logger.info(f"Path traversal successful: {filename}")
                return  # One success is enough

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"file_upload_{self.target_domain}")

        vuln_path = self.output_dir / f"file_upload_vulns_{self.target_domain}.json"
        with open(vuln_path, "w") as f:
            json.dump({
                "target": self.target,
                "timestamp": timestamp_now(),
                "uploaded_files": self.uploaded_files,
                "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            }, f, indent=2)
        paths["vulnerabilities"] = str(vuln_path)

        return paths


async def main():
    parser = argparse.ArgumentParser(description="File Upload tester")
    parser.add_argument("-t", "--target", required=True, help="Target upload URL")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("--file-field", default="file", help="File input field name")
    parser.add_argument("--auth-cookie", help="Authentication cookie")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    tester = FileUploadTester(
        target=args.target,
        output_dir=args.output,
        proxy=args.proxy,
        file_field=args.file_field,
        auth_cookie=args.auth_cookie,
        verbose=args.verbose,
    )

    result = await tester.test()
    paths = tester.save_results(result)

    print(f"\n{'='*60}")
    print(f"File Upload Testing Complete")
    print(f"{'='*60}")
    print(f"Files Uploaded: {len(tester.uploaded_files)}")
    print(f"Vulnerabilities: {len(tester.vulnerabilities)}")
    for name, path in paths.items():
        print(f"  {name}: {path}")


if __name__ == "__main__":
    asyncio.run(main())
