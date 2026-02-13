#!/usr/bin/env python3
"""
GraphQL introspection and schema discovery module.

Usage:
    python graphql_introspect.py --target https://example.com/graphql --output results/
"""

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.http_client import AsyncHTTPClient
from core.result_manager import ResultManager, ScanResult, Finding, Severity
from core.utils import setup_logging, load_config, normalize_url, extract_domain, timestamp_now, ensure_dir

logger = setup_logging("graphql_introspect")


@dataclass
class GraphQLField:
    """Represents a GraphQL field."""

    name: str
    type_name: str
    args: List[Dict[str, str]] = field(default_factory=list)
    description: str = ""
    is_deprecated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type_name,
            "args": self.args,
            "description": self.description,
            "is_deprecated": self.is_deprecated,
        }


@dataclass
class GraphQLType:
    """Represents a GraphQL type."""

    name: str
    kind: str  # OBJECT, INPUT_OBJECT, ENUM, SCALAR, INTERFACE, UNION
    fields: List[GraphQLField] = field(default_factory=list)
    enum_values: List[str] = field(default_factory=list)
    description: str = ""
    interfaces: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "fields": [f.to_dict() for f in self.fields],
            "enum_values": self.enum_values,
            "description": self.description,
            "interfaces": self.interfaces,
        }


@dataclass
class GraphQLSchema:
    """Represents a GraphQL schema."""

    query_type: str = ""
    mutation_type: str = ""
    subscription_type: str = ""
    types: List[GraphQLType] = field(default_factory=list)
    directives: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query_type": self.query_type,
            "mutation_type": self.mutation_type,
            "subscription_type": self.subscription_type,
            "types": [t.to_dict() for t in self.types],
            "directives": self.directives,
        }


class GraphQLIntrospector:
    """
    GraphQL introspection and security analysis.

    Features:
    - Schema introspection
    - Endpoint discovery
    - Query/Mutation enumeration
    - Security misconfiguration detection
    - Sensitive field discovery
    """

    # Common GraphQL endpoint paths
    GRAPHQL_PATHS = [
        "/graphql",
        "/graphiql",
        "/playground",
        "/api/graphql",
        "/v1/graphql",
        "/v2/graphql",
        "/query",
        "/gql",
        "/graphql/console",
        "/graphql/playground",
        "/_graphql",
        "/api/v1/graphql",
        "/api/v2/graphql",
    ]

    # Full introspection query
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }

    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }

    fragment InputValue on __InputValue {
      name
      description
      type {
        ...TypeRef
      }
      defaultValue
    }

    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
    """

    # Simple introspection query (for restricted endpoints)
    SIMPLE_INTROSPECTION = """
    query {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          kind
          fields {
            name
            type {
              name
              kind
            }
          }
        }
      }
    }
    """

    # Sensitive field patterns to look for
    SENSITIVE_FIELDS = [
        "password", "passwd", "secret", "token", "key", "apikey",
        "api_key", "auth", "credential", "private", "admin",
        "ssn", "social_security", "credit_card", "card_number",
        "cvv", "pin", "dob", "date_of_birth", "salary",
        "bank", "account", "routing", "internal", "debug",
    ]

    def __init__(
        self,
        target: str,
        output_dir: str = "results",
        config: Optional[Dict] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
        verbose: bool = False,
    ):
        self.target = normalize_url(target)
        self.target_domain = extract_domain(target)
        self.output_dir = Path(output_dir)
        self.config = config or {}
        self.proxy = proxy
        self.timeout = timeout
        self.verbose = verbose

        self.graphql_endpoint: Optional[str] = None
        self.schema: Optional[GraphQLSchema] = None
        self.introspection_enabled: bool = False
        self.sensitive_fields: List[Dict[str, str]] = []
        self.security_issues: List[Dict[str, str]] = []

        self.result_manager = ResultManager(output_dir)
        ensure_dir(self.output_dir)

    async def introspect(self) -> ScanResult:
        """Run GraphQL introspection and return results."""
        result = ScanResult(
            tool="graphql_introspect",
            target=self.target,
            config={
                "timeout": self.timeout,
            },
        )

        logger.info(f"Starting GraphQL introspection for: {self.target}")

        try:
            # Discover GraphQL endpoint
            await self._discover_endpoint()

            if not self.graphql_endpoint:
                result.add_error("No GraphQL endpoint found")
                logger.warning("No GraphQL endpoint found")
                result.finalize()
                return result

            logger.info(f"GraphQL endpoint found: {self.graphql_endpoint}")

            # Test introspection
            await self._test_introspection()

            if self.introspection_enabled:
                result.add_finding(Finding(
                    title="GraphQL Introspection Enabled",
                    severity=Severity.MEDIUM,
                    description="GraphQL introspection is enabled, allowing schema discovery",
                    url=self.graphql_endpoint,
                    remediation="Disable introspection in production environments",
                    cwe_id="CWE-200",
                ))

                # Parse schema
                self._analyze_schema()

                # Find sensitive fields
                self._find_sensitive_fields()

            # Check for security misconfigurations
            await self._check_security()

            # Add findings for sensitive fields
            for field_info in self.sensitive_fields:
                result.add_finding(Finding(
                    title=f"Sensitive Field Exposed: {field_info['field']}",
                    severity=Severity.HIGH,
                    description=f"Potentially sensitive field '{field_info['field']}' found in type '{field_info['type']}'",
                    url=self.graphql_endpoint,
                    metadata=field_info,
                ))

            # Add security issue findings
            for issue in self.security_issues:
                result.add_finding(Finding(
                    title=issue["title"],
                    severity=Severity(issue["severity"]),
                    description=issue["description"],
                    url=self.graphql_endpoint,
                    evidence=issue.get("evidence", ""),
                    remediation=issue.get("remediation", ""),
                ))

            # Calculate statistics
            if self.schema:
                result.stats = {
                    "endpoint": self.graphql_endpoint,
                    "introspection_enabled": self.introspection_enabled,
                    "total_types": len(self.schema.types),
                    "query_fields": len([t for t in self.schema.types if t.name == self.schema.query_type][0].fields) if self.schema.query_type else 0,
                    "mutation_fields": self._count_mutations(),
                    "sensitive_fields": len(self.sensitive_fields),
                    "security_issues": len(self.security_issues),
                }

        except Exception as e:
            result.add_error(f"Introspection error: {e}")
            logger.error(f"Introspection error: {e}")

        result.finalize()
        return result

    async def _discover_endpoint(self):
        """Discover the GraphQL endpoint."""
        logger.info("Discovering GraphQL endpoint...")

        # If target looks like a GraphQL endpoint, use it directly
        if any(path in self.target.lower() for path in ['/graphql', '/gql', '/query']):
            self.graphql_endpoint = self.target
            return

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
            max_retries=1,
        ) as client:
            base_url = self.target.rstrip('/')

            for path in self.GRAPHQL_PATHS:
                url = f"{base_url}{path}"
                try:
                    # Test with a simple query
                    response = await client.post(
                        url,
                        json={"query": "{ __typename }"},
                        headers={"Content-Type": "application/json"},
                    )

                    # Check if it's a GraphQL endpoint
                    if response.ok or response.status == 400:
                        try:
                            data = json.loads(response.body)
                            if "data" in data or "errors" in data:
                                self.graphql_endpoint = url
                                logger.info(f"Found GraphQL endpoint: {url}")
                                return
                        except json.JSONDecodeError:
                            pass

                except Exception as e:
                    logger.debug(f"Error testing {url}: {e}")

    async def _test_introspection(self):
        """Test if introspection is enabled."""
        if not self.graphql_endpoint:
            return

        logger.info("Testing introspection...")

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
        ) as client:
            # Try full introspection
            response = await client.post(
                self.graphql_endpoint,
                json={"query": self.INTROSPECTION_QUERY},
                headers={"Content-Type": "application/json"},
            )

            if response.ok:
                try:
                    data = json.loads(response.body)
                    if "data" in data and data["data"].get("__schema"):
                        self.introspection_enabled = True
                        self._parse_schema(data["data"]["__schema"])
                        logger.info("Full introspection successful")
                        return
                except json.JSONDecodeError:
                    pass

            # Try simple introspection
            response = await client.post(
                self.graphql_endpoint,
                json={"query": self.SIMPLE_INTROSPECTION},
                headers={"Content-Type": "application/json"},
            )

            if response.ok:
                try:
                    data = json.loads(response.body)
                    if "data" in data and data["data"].get("__schema"):
                        self.introspection_enabled = True
                        self._parse_schema(data["data"]["__schema"])
                        logger.info("Simple introspection successful")
                except json.JSONDecodeError:
                    pass

    def _parse_schema(self, schema_data: Dict):
        """Parse the introspection schema data."""
        self.schema = GraphQLSchema()

        # Root types
        if schema_data.get("queryType"):
            self.schema.query_type = schema_data["queryType"].get("name", "")
        if schema_data.get("mutationType"):
            self.schema.mutation_type = schema_data["mutationType"].get("name", "")
        if schema_data.get("subscriptionType"):
            self.schema.subscription_type = schema_data["subscriptionType"].get("name", "")

        # Parse types
        for type_data in schema_data.get("types", []):
            if type_data.get("name", "").startswith("__"):
                continue  # Skip introspection types

            gql_type = GraphQLType(
                name=type_data.get("name", ""),
                kind=type_data.get("kind", ""),
                description=type_data.get("description", "") or "",
            )

            # Parse fields
            for field_data in type_data.get("fields", []) or []:
                gql_field = GraphQLField(
                    name=field_data.get("name", ""),
                    type_name=self._get_type_name(field_data.get("type", {})),
                    description=field_data.get("description", "") or "",
                    is_deprecated=field_data.get("isDeprecated", False),
                )

                # Parse arguments
                for arg_data in field_data.get("args", []) or []:
                    gql_field.args.append({
                        "name": arg_data.get("name", ""),
                        "type": self._get_type_name(arg_data.get("type", {})),
                    })

                gql_type.fields.append(gql_field)

            # Parse enum values
            for enum_data in type_data.get("enumValues", []) or []:
                gql_type.enum_values.append(enum_data.get("name", ""))

            # Parse interfaces
            for interface in type_data.get("interfaces", []) or []:
                gql_type.interfaces.append(interface.get("name", ""))

            self.schema.types.append(gql_type)

        # Parse directives
        for directive in schema_data.get("directives", []) or []:
            self.schema.directives.append(directive.get("name", ""))

    def _get_type_name(self, type_data: Dict) -> str:
        """Extract type name from nested type structure."""
        if not type_data:
            return ""

        kind = type_data.get("kind", "")
        name = type_data.get("name", "")

        if name:
            return name

        if kind == "NON_NULL":
            return f"{self._get_type_name(type_data.get('ofType', {}))}!"
        elif kind == "LIST":
            return f"[{self._get_type_name(type_data.get('ofType', {}))}]"

        of_type = type_data.get("ofType")
        if of_type:
            return self._get_type_name(of_type)

        return ""

    def _analyze_schema(self):
        """Analyze the parsed schema for security issues."""
        if not self.schema:
            return

        # Check for dangerous mutations
        if self.schema.mutation_type:
            mutation_type = next((t for t in self.schema.types if t.name == self.schema.mutation_type), None)
            if mutation_type:
                dangerous_mutations = ["delete", "remove", "drop", "admin", "execute", "run"]
                for field in mutation_type.fields:
                    if any(d in field.name.lower() for d in dangerous_mutations):
                        self.security_issues.append({
                            "title": f"Dangerous Mutation: {field.name}",
                            "severity": "medium",
                            "description": f"Potentially dangerous mutation '{field.name}' found",
                            "remediation": "Ensure proper authorization for dangerous mutations",
                        })

    def _find_sensitive_fields(self):
        """Find potentially sensitive fields in the schema."""
        if not self.schema:
            return

        for gql_type in self.schema.types:
            for field in gql_type.fields:
                field_lower = field.name.lower()
                for sensitive in self.SENSITIVE_FIELDS:
                    if sensitive in field_lower:
                        self.sensitive_fields.append({
                            "type": gql_type.name,
                            "field": field.name,
                            "field_type": field.type_name,
                            "pattern": sensitive,
                        })
                        break

    async def _check_security(self):
        """Check for common GraphQL security issues."""
        if not self.graphql_endpoint:
            return

        async with AsyncHTTPClient(
            timeout=self.timeout,
            proxy=self.proxy,
        ) as client:
            # Test for query depth/complexity limits
            deep_query = self._generate_deep_query(10)
            response = await client.post(
                self.graphql_endpoint,
                json={"query": deep_query},
                headers={"Content-Type": "application/json"},
            )

            if response.ok:
                try:
                    data = json.loads(response.body)
                    if "data" in data and "errors" not in data:
                        self.security_issues.append({
                            "title": "No Query Depth Limit",
                            "severity": "medium",
                            "description": "GraphQL endpoint accepts deeply nested queries without limits",
                            "evidence": "Successfully executed query with depth 10",
                            "remediation": "Implement query depth limiting",
                        })
                except json.JSONDecodeError:
                    pass

            # Test for batching
            batch_query = [
                {"query": "{ __typename }"},
                {"query": "{ __typename }"},
                {"query": "{ __typename }"},
            ]
            response = await client.post(
                self.graphql_endpoint,
                json=batch_query,
                headers={"Content-Type": "application/json"},
            )

            if response.ok:
                try:
                    data = json.loads(response.body)
                    if isinstance(data, list) and len(data) == 3:
                        self.security_issues.append({
                            "title": "Query Batching Enabled",
                            "severity": "low",
                            "description": "GraphQL endpoint accepts batched queries",
                            "remediation": "Consider limiting batch size to prevent abuse",
                        })
                except json.JSONDecodeError:
                    pass

            # Test for field suggestions
            response = await client.post(
                self.graphql_endpoint,
                json={"query": "{ nonexistentfield12345 }"},
                headers={"Content-Type": "application/json"},
            )

            if response.ok:
                try:
                    data = json.loads(response.body)
                    errors = data.get("errors", [])
                    for error in errors:
                        msg = str(error.get("message", "")).lower()
                        if "did you mean" in msg or "suggestions" in msg:
                            self.security_issues.append({
                                "title": "Field Suggestions Enabled",
                                "severity": "info",
                                "description": "GraphQL endpoint provides field name suggestions in error messages",
                                "evidence": error.get("message", ""),
                                "remediation": "Disable field suggestions in production",
                            })
                            break
                except json.JSONDecodeError:
                    pass

    def _generate_deep_query(self, depth: int) -> str:
        """Generate a deeply nested query for testing."""
        if not self.schema or not self.schema.query_type:
            return "{ __typename " * depth + "}" * depth

        # Try to find a self-referencing type
        query_type = next((t for t in self.schema.types if t.name == self.schema.query_type), None)
        if query_type and query_type.fields:
            field_name = query_type.fields[0].name
            return "{ " + f"{field_name} {{ __typename " * depth + "}" * (depth + 1)

        return "{ __typename " * depth + "}" * depth

    def _count_mutations(self) -> int:
        """Count mutation fields."""
        if not self.schema or not self.schema.mutation_type:
            return 0
        mutation_type = next((t for t in self.schema.types if t.name == self.schema.mutation_type), None)
        return len(mutation_type.fields) if mutation_type else 0

    def save_results(self, result: ScanResult) -> Dict[str, str]:
        """Save results to files."""
        paths = self.result_manager.save(result, f"graphql_{self.target_domain}")

        if self.schema:
            # Save schema JSON
            schema_path = self.output_dir / f"graphql_schema_{self.target_domain}.json"
            with open(schema_path, "w") as f:
                json.dump(
                    {
                        "endpoint": self.graphql_endpoint,
                        "timestamp": timestamp_now(),
                        "introspection_enabled": self.introspection_enabled,
                        "schema": self.schema.to_dict(),
                        "sensitive_fields": self.sensitive_fields,
                        "security_issues": self.security_issues,
                    },
                    f,
                    indent=2,
                )
            paths["schema"] = str(schema_path)

            # Save SDL format (simplified)
            sdl_path = self.output_dir / f"graphql_schema_{self.target_domain}.graphql"
            with open(sdl_path, "w") as f:
                f.write(self._generate_sdl())
            paths["sdl"] = str(sdl_path)

        return paths

    def _generate_sdl(self) -> str:
        """Generate GraphQL SDL from parsed schema."""
        if not self.schema:
            return ""

        lines = []
        lines.append(f"# GraphQL Schema for {self.target}")
        lines.append(f"# Generated at {timestamp_now()}")
        lines.append("")

        for gql_type in self.schema.types:
            if gql_type.name.startswith("__"):
                continue

            if gql_type.kind == "OBJECT":
                interfaces = f" implements {' & '.join(gql_type.interfaces)}" if gql_type.interfaces else ""
                lines.append(f"type {gql_type.name}{interfaces} {{")
                for field in gql_type.fields:
                    args_str = ""
                    if field.args:
                        args_list = [f"{a['name']}: {a['type']}" for a in field.args]
                        args_str = f"({', '.join(args_list)})"
                    lines.append(f"  {field.name}{args_str}: {field.type_name}")
                lines.append("}")
                lines.append("")

            elif gql_type.kind == "INPUT_OBJECT":
                lines.append(f"input {gql_type.name} {{")
                for field in gql_type.fields:
                    lines.append(f"  {field.name}: {field.type_name}")
                lines.append("}")
                lines.append("")

            elif gql_type.kind == "ENUM":
                lines.append(f"enum {gql_type.name} {{")
                for value in gql_type.enum_values:
                    lines.append(f"  {value}")
                lines.append("}")
                lines.append("")

        return "\n".join(lines)


async def main():
    parser = argparse.ArgumentParser(
        description="GraphQL introspection and schema discovery"
    )
    parser.add_argument("-t", "--target", required=True, help="Target URL or GraphQL endpoint")
    parser.add_argument("-o", "--output", default="results", help="Output directory")
    parser.add_argument("-c", "--config", help="Config file path")
    parser.add_argument("-p", "--proxy", help="Proxy URL")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    config = {}
    if args.config:
        config = load_config(args.config)

    introspector = GraphQLIntrospector(
        target=args.target,
        output_dir=args.output,
        config=config,
        proxy=args.proxy,
        timeout=args.timeout,
        verbose=args.verbose,
    )

    result = await introspector.introspect()
    paths = introspector.save_results(result)

    print(f"\n{'='*60}")
    print(f"GraphQL Introspection Complete: {args.target}")
    print(f"{'='*60}")
    print(f"Endpoint: {introspector.graphql_endpoint or 'Not found'}")
    print(f"Introspection Enabled: {introspector.introspection_enabled}")

    if introspector.schema:
        print(f"Types Found: {len(introspector.schema.types)}")
        print(f"Query Type: {introspector.schema.query_type}")
        print(f"Mutation Type: {introspector.schema.mutation_type or 'None'}")
        print(f"Sensitive Fields: {len(introspector.sensitive_fields)}")
        print(f"Security Issues: {len(introspector.security_issues)}")

    print(f"\nResults saved to:")
    for name, path in paths.items():
        print(f"  {name}: {path}")

    # Show security issues
    if introspector.security_issues:
        print(f"\n*** SECURITY ISSUES ***")
        for issue in introspector.security_issues:
            print(f"  [{issue['severity'].upper()}] {issue['title']}")


if __name__ == "__main__":
    asyncio.run(main())
