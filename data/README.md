# Dataset construction provenance and sharing policy

This document describes the provenance, acquisition procedure, and redistribution status of the evaluation corpus used in Beyond Random Splits: Class-Conditioned Site Exposure and Attribution Change in Phishing URL Evaluation.

## Corpus provenance and composition

The primary evaluation corpus contains 124,154 DNS-host URLs: 71,565 phishing URLs from a frozen PhishTank online-valid snapshot dated 2026-08-17 and 52,589 benign URLs obtained from the Common Crawl CC-MAIN-2026-30 index using a frozen 2,500-site Tranco frame. The final post-quarantine corpus contains 29,091 private-PSL registrable sites. Five mixed-label sites comprising 175 rows were quarantined as whole sites; no individual labels were reclassified.

## Redistribution policy

Raw URL strings and the combined derived corpus are not redistributed directly while multi-source redistribution eligibility is being verified. Source materials remain subject to the terms of PhishTank, Common Crawl, Tranco, and the Public Suffix List.

## Included reproducibility materials

- acquisition and parsing code
- frozen PSL and parser contracts
- split definitions and seed documentation
- canonical aggregate results, including frozen bootstrap interval summaries
- SHA-256 manifests and environment specifications

The MIT License applies to this repository's code and documentation, not to third-party source data or materials.
