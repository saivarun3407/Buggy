-- KG schema v005 — node labels for the recon-store projection.
--
-- ``buggy.pipeline.graph_export`` projects the pipeline's recon records
-- into the graph (Host -> IP / Port / Service -> Endpoint / Operation ->
-- Parameter, plus Technology, ApiSpec, KnownIssue and GraphQL). Host,
-- Service and Technology are already constrained by V001 / V004; this
-- adds the labels the projection introduces.
--
-- Same ``(key, engagement)`` composite invariant as V001/V003/V004: the
-- same projection key in two engagements is two nodes (multi-tenant);
-- the same key in one engagement is one node (idempotent MERGE, so a
-- second projection of an unchanged store creates nothing).

CREATE CONSTRAINT ip_key_engagement IF NOT EXISTS
  FOR (n:IP) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT port_key_engagement IF NOT EXISTS
  FOR (n:Port) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT endpoint_key_engagement IF NOT EXISTS
  FOR (n:Endpoint) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT api_spec_key_engagement IF NOT EXISTS
  FOR (n:ApiSpec) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT operation_key_engagement IF NOT EXISTS
  FOR (n:Operation) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT parameter_key_engagement IF NOT EXISTS
  FOR (n:Parameter) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT known_issue_key_engagement IF NOT EXISTS
  FOR (n:KnownIssue) REQUIRE (n.key, n.engagement) IS UNIQUE;
CREATE CONSTRAINT graphql_key_engagement IF NOT EXISTS
  FOR (n:GraphQL) REQUIRE (n.key, n.engagement) IS UNIQUE;
