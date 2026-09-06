# Architecture

PressWarden separates **discovery**, **suite orchestration**, **focused checks**, and **optional enrichment**. `lib/_lib.sh` validates and indexes WordPress roots once, caches the inventory, and exposes outermost tree roots to recursive scanners so nested sites are not double-scanned. `lib/_runner.sh` executes named checks and writes human/JSON summaries. Provider-specific APIs are optional enrichment; filesystem, WordPress, PHP, and database scanning do not depend on a hosting vendor.
