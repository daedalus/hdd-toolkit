# INVESTIGATION.md

## Purpose
This file tracks external techniques, field observations, and reverse-engineering notes that inform hdd-toolkit features, tests, and safety guardrails.

## Source categories
- vendor documentation
- academic papers
- conference talks
- reverse-engineering blogs
- practitioner forums
- empirical lab validation

## Evidence scale
- high: vendor doc, academic paper, or reproduced in lab
- medium: multiple independent practitioner reports
- low: single report or unverified anecdote

## Safety rules for forum-derived material
- paraphrase all forum content
- do not copy long text verbatim
- do not reproduce proprietary tool workflows step-by-step
- mark destructive procedures as unverified unless reproduced
- prefer signatures, symptoms, and diagnostic heuristics over repair instructions

## Practitioner reports

### HDDGuru / AceLab forum mining
Status: initial pass
Confidence: medium
Type: practitioner reports

#### Observed recurring value
- failure signatures exposed through IDENTIFY strings
- translator-loss terminology
- service-area and ROM mismatch symptoms
- controller-family naming conventions
- readiness-loss and empty-read patterns
- diagnostic decision trees used by recovery practitioners

#### Candidate signatures for toolkit support
- SATAFIRM S11
  - category: firmware_translator_failure
  - confidence: medium
  - likely meaning: SSD firmware failure state discussed by recovery practitioners
  - caution: all-zero logical reads do not by themselves prove media erasure
  - good toolkit uses:
    - identify-string recognizer
    - warning classification
    - fixture-based parser tests
    - research-note cross references

#### Proposed downstream code targets
- firmware detection heuristics for suspicious identify strings
- recovery-state classification helpers
- structured signature dictionaries under src/hdd_toolkit/data/signatures/
- tests using sanitized identify dumps and expected classifications

#### Validation needed before code promotion
- collect at least two independent examples per signature
- verify whether symptom is vendor-family-specific or generic
- separate "diagnostic clue" from "repair recommendation"
- label whether a signature affects HDD, SATA SSD, NVMe SSD, or bridge devices

## Planned signature schema
- match string or predicate
- category
- device class
- confidence
- short description
- recommended non-destructive actions
- source bucket
- validation status

## Promotion rules
Forum-derived material may move into executable heuristics only if:
- it is independently corroborated, or
- it is clearly labeled heuristic with conservative output wording
