"""
SHADOW Bug Bounty Framework - Phase 2: Discovery
"""

from .js_analyzer import JSAnalyzer
from .directory_bruteforce import DirectoryBruteforcer
from .parameter_discovery import ParameterDiscovery
from .api_endpoint_extractor import APIEndpointExtractor
from .graphql_introspect import GraphQLIntrospector
from .openapi_discovery import OpenAPIDiscovery
from .oauth_discovery import OAuthDiscovery
from .framework_fingerprinter import FrameworkFingerprinter
from .admin_panel_detector import AdminPanelDetector

__all__ = [
    "JSAnalyzer",
    "DirectoryBruteforcer",
    "ParameterDiscovery",
    "APIEndpointExtractor",
    "GraphQLIntrospector",
    "OpenAPIDiscovery",
    "OAuthDiscovery",
    "FrameworkFingerprinter",
    "AdminPanelDetector",
]
