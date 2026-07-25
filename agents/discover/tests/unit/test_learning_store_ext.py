"""Tests for learning store serialization of new fields.

Tests round-trip serialization of graphql_schemas, source_routes,
known_404_paths, reachable_endpoints, and the new helper functions
record_known_404 and record_reachable_endpoint.
"""

import time


from discover_agent.learning_store import (
    GraphQLSchemaCache,
    SessionLearnings,
    load_learnings,
    record_known_404,
    record_reachable_endpoint,
    save_learnings,
)


class TestGraphQLSchemaSerialization:
    """Tests for GraphQL schema cache round-trip serialization."""

    def test_save_and_load_graphql_schemas(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VULTURE_LEARNINGS_DIR", str(tmp_path))
        # Force module to pick up the new env var
        import discover_agent.learning_store as ls
        monkeypatch.setattr(ls, "_LEARNINGS_DIR", str(tmp_path))

        url = "http://example.com"
        learnings = SessionLearnings()
        learnings.graphql_schemas["/graphql"] = GraphQLSchemaCache(
            path="/graphql",
            variant="apollo",
            queries=["users", "posts", "me"],
            mutations=["createUser", "deleteUser"],
            subscriptions=["onUserCreated"],
            types=["User", "Post", "Query", "Mutation"],
            introspection_enabled=True,
            last_updated=1000000.0,
        )
        learnings.graphql_schemas["/api/graphql"] = GraphQLSchemaCache(
            path="/api/graphql",
            variant="hasura",
            queries=["orders"],
            mutations=[],
            introspection_enabled=False,
            last_updated=2000000.0,
        )

        save_learnings(url, learnings)
        loaded = load_learnings(url)

        assert len(loaded.graphql_schemas) == 2

        gql = loaded.graphql_schemas["/graphql"]
        assert gql.path == "/graphql"
        assert gql.variant == "apollo"
        assert gql.queries == ["users", "posts", "me"]
        assert gql.mutations == ["createUser", "deleteUser"]
        assert gql.subscriptions == ["onUserCreated"]
        assert gql.types == ["User", "Post", "Query", "Mutation"]
        assert gql.introspection_enabled is True
        assert gql.last_updated == 1000000.0

        api_gql = loaded.graphql_schemas["/api/graphql"]
        assert api_gql.variant == "hasura"
        assert api_gql.introspection_enabled is False


class TestSourceRoutesSerialization:
    """Tests for source_routes round-trip serialization."""

    def test_save_and_load_source_routes(self, tmp_path, monkeypatch):
        import discover_agent.learning_store as ls
        monkeypatch.setattr(ls, "_LEARNINGS_DIR", str(tmp_path))

        url = "http://example.com"
        learnings = SessionLearnings(
            source_routes=["/api/users", "/api/auth/login", "/api/orders/{id}"],
        )

        save_learnings(url, learnings)
        loaded = load_learnings(url)

        assert loaded.source_routes == ["/api/users", "/api/auth/login", "/api/orders/{id}"]

    def test_caps_source_routes(self, tmp_path, monkeypatch):
        import discover_agent.learning_store as ls
        monkeypatch.setattr(ls, "_LEARNINGS_DIR", str(tmp_path))

        url = "http://example.com"
        learnings = SessionLearnings(
            source_routes=[f"/api/route/{i}" for i in range(600)],
        )

        save_learnings(url, learnings)
        loaded = load_learnings(url)

        assert len(loaded.source_routes) == 500


class TestKnown404Serialization:
    """Tests for known_404_paths round-trip serialization."""

    def test_save_and_load_known_404s(self, tmp_path, monkeypatch):
        import discover_agent.learning_store as ls
        monkeypatch.setattr(ls, "_LEARNINGS_DIR", str(tmp_path))

        url = "http://example.com"
        learnings = SessionLearnings(
            known_404_paths=["/admin", "/debug", "/.env"],
        )

        save_learnings(url, learnings)
        loaded = load_learnings(url)

        assert loaded.known_404_paths == ["/admin", "/debug", "/.env"]


class TestReachableEndpointsSerialization:
    """Tests for reachable_endpoints round-trip serialization."""

    def test_save_and_load_reachable(self, tmp_path, monkeypatch):
        import discover_agent.learning_store as ls
        monkeypatch.setattr(ls, "_LEARNINGS_DIR", str(tmp_path))

        url = "http://example.com"
        learnings = SessionLearnings(
            reachable_endpoints=["/api/users", "/api/health", "/api/auth/session"],
        )

        save_learnings(url, learnings)
        loaded = load_learnings(url)

        assert loaded.reachable_endpoints == ["/api/users", "/api/health", "/api/auth/session"]


class TestRecordKnown404:
    """Tests for record_known_404 helper."""

    def test_records_new_404(self):
        learnings = SessionLearnings()
        record_known_404(learnings, "/admin")
        assert "/admin" in learnings.known_404_paths

    def test_no_duplicates(self):
        learnings = SessionLearnings(known_404_paths=["/admin"])
        record_known_404(learnings, "/admin")
        assert learnings.known_404_paths.count("/admin") == 1

    def test_removes_from_reachable(self):
        learnings = SessionLearnings(
            reachable_endpoints=["/admin", "/api/users"],
        )
        record_known_404(learnings, "/admin")
        assert "/admin" not in learnings.reachable_endpoints
        assert "/api/users" in learnings.reachable_endpoints
        assert "/admin" in learnings.known_404_paths


class TestRecordReachableEndpoint:
    """Tests for record_reachable_endpoint helper."""

    def test_records_new_reachable(self):
        learnings = SessionLearnings()
        record_reachable_endpoint(learnings, "/api/users")
        assert "/api/users" in learnings.reachable_endpoints

    def test_no_duplicates(self):
        learnings = SessionLearnings(reachable_endpoints=["/api/users"])
        record_reachable_endpoint(learnings, "/api/users")
        assert learnings.reachable_endpoints.count("/api/users") == 1

    def test_removes_from_known_404(self):
        learnings = SessionLearnings(
            known_404_paths=["/api/users", "/admin"],
        )
        record_reachable_endpoint(learnings, "/api/users")
        assert "/api/users" not in learnings.known_404_paths
        assert "/admin" in learnings.known_404_paths
        assert "/api/users" in learnings.reachable_endpoints


class TestFullRoundTrip:
    """Test complete save/load with all new fields populated."""

    def test_full_round_trip(self, tmp_path, monkeypatch):
        import discover_agent.learning_store as ls
        monkeypatch.setattr(ls, "_LEARNINGS_DIR", str(tmp_path))

        url = "http://staging.example.com"
        learnings = SessionLearnings(
            insights=["Auth uses JWT", "Rate limiting on /api/auth"],
            auth_type="jwt",
            technologies=["express", "GraphQL"],
            source_routes=["/api/users", "/api/auth/login"],
            known_404_paths=["/admin", "/.env"],
            reachable_endpoints=["/api/users", "/api/health"],
        )
        learnings.graphql_schemas["/graphql"] = GraphQLSchemaCache(
            path="/graphql", variant="apollo",
            queries=["users", "me"], mutations=["createUser"],
            introspection_enabled=True, last_updated=time.time(),
        )

        save_learnings(url, learnings)
        loaded = load_learnings(url)

        assert loaded.insights == learnings.insights
        assert loaded.auth_type == "jwt"
        assert loaded.technologies == ["express", "GraphQL"]
        assert loaded.source_routes == ["/api/users", "/api/auth/login"]
        assert loaded.known_404_paths == ["/admin", "/.env"]
        assert loaded.reachable_endpoints == ["/api/users", "/api/health"]
        assert "/graphql" in loaded.graphql_schemas
        assert loaded.graphql_schemas["/graphql"].queries == ["users", "me"]
