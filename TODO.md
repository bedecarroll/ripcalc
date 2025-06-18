<!--
  TODO.md - Feature roadmap for ripcalc
  Generated suggestions for future enhancements.
  Update and prioritize these items as work progresses.
-->
# ripcalc Feature Roadmap

Below is a non-exhaustive list of potential features and enhancements for ripcalc to better serve network engineers. Each item can be scoped, estimated, and scheduled based on priority.

## 1. Supernet Summarization
- Aggregate a list of networks into minimal enclosing supernet(s).
- Example: combine 192.168.1.0/24 + 192.168.2.0/24 → 192.168.0.0/23.

## 2. Overlap & Conflict Detection
- Given multiple subnets, detect overlaps or gaps.
- Report conflicting pairs and summary of coverage.

## 3. VLSM / Multi-Pool Calculator
- Input: root network (e.g., 10.0.0.0/16) and required host counts.
- Output: optimal subnet allocations per pool (largest-first packing).

## 4. CSV / Table Output Mode
- Render results in CSV or aligned-column tables.
- Facilitate import into spreadsheets or network inventory systems.

## 5. ACL-Friendly Output
- Generate Cisco IOS/ASA access-list entries or Juniper firewall filters.
- Convert computed ranges into `permit`/`deny` statements.

## 6. DHCP-Pool Helpers
- Suggest DHCP pool ranges (e.g., .10–.200) and gateway addresses.
- Validate pool size vs. subnet capacity.

## 7. Binary & Hex Visualization
- Side-by-side binary bitmaps of address vs. mask.
- ASCII “bit grid” diagram showing network/host bits.

## 8. IPv6 SLAAC / EUI-64 Helpers
- Derive full IPv6 EUI-64 addresses from MAC or prefix.
- Support privacy and stable IID generation.

## 9. Bulk File Processing & Reporting
- Read lists of subnets from a file.
- Produce summary report (counts, overlaps, supernets).

## 10. Plugin Hooks & API Mode
- Expose JSON-RPC or library API for programmatic integration.
- Allow plugins to extend calc, formatting, or output targets.

---
_Feel free to reorder, refine, or split these items into issues as needed._
