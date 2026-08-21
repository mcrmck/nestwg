# Sanitized WireGuard export shapes

These fixtures contain synthetic keys, addresses, and endpoints. They model
common `wg-quick` export shapes without claiming compatibility with a named
provider or containing live account material.

The corpus deliberately covers ignored `wg-quick` metadata and hooks. Tests
must only parse these files; hooks are never executed. Add a sanitized fixture
and expected behavior when fixing an importer compatibility issue.
