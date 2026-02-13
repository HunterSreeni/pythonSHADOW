"""
SHADOW Bug Bounty Framework - Phase 3: Vulnerability Testing
"""

from .injection.sqli_tester import SQLiTester
from .injection.xss_tester import XSSTester
from .injection.xxe_tester import XXETester
from .injection.ssti_tester import SSTITester
from .injection.command_injection import CommandInjectionTester

from .access.idor_tester import IDORTester
from .access.privilege_escalation import PrivilegeEscalationTester
from .access.access_control import AccessControlTester

from .auth.jwt_tester import JWTTester
from .auth.login_bypass import LoginBypassTester
from .auth.session_tester import SessionTester
from .auth.password_reset import PasswordResetTester

from .ssrf_tester import SSRFTester
from .csrf_tester import CSRFTester
from .race_condition import RaceConditionTester
from .file_upload import FileUploadTester
from .business_logic import BusinessLogicTester

__all__ = [
    # Injection
    "SQLiTester",
    "XSSTester",
    "XXETester",
    "SSTITester",
    "CommandInjectionTester",
    # Access Control
    "IDORTester",
    "PrivilegeEscalationTester",
    "AccessControlTester",
    # Authentication
    "JWTTester",
    "LoginBypassTester",
    "SessionTester",
    "PasswordResetTester",
    # Other Vulnerabilities
    "SSRFTester",
    "CSRFTester",
    "RaceConditionTester",
    "FileUploadTester",
    "BusinessLogicTester",
]
