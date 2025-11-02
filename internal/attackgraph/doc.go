// Package attackgraph builds the RedOps asset graph from the SQLite store
// (hosts → services → findings → techniques) and exports it as JSON, Cypher,
// or DOT. An optional Neo4j sync pushes the same graph when REDOPS_NEO4J_URI
// is configured; everything else works fully offline.
package attackgraph
