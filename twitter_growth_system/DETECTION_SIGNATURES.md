# Botnet Detection Signatures & Behavioral Analysis

This document outlines the primary methods platforms use to detect and mitigate mass account creation and automated spam operations.

## 1. Network Layer Fingerprinting

### ASN & IP Reputation
*   **Datacenter vs. Residential:** Platforms query IP databases (e.g., MaxMind, IPinfo) to determine the ISP type. Traffic from hosting providers (AWS, DigitalOcean) or known proxy/VPN ASNs is flagged immediately.
*   **Subnet Blocking:** If multiple accounts originate from the same `/24` subnet, the entire range may be blacklisted.
*   **Velocity Checks:** Tracking the number of requests per IP per minute. "Low and slow" attacks attempt to evade this but are often caught by longer-term correlation.

### TLS Fingerprinting (JA3/JA4)
*   **Client Hello Analysis:** The specific order of ciphers, extensions, and elliptic curves in the TLS Client Hello packet creates a unique fingerprint.
*   **Mismatch Detection:** If a client claims to be "Chrome on Windows" (User-Agent) but its TLS fingerprint matches a Python `requests` library or a headless browser, it is blocked.

## 2. Behavioral Biometrics

### Input Telemetry
*   **Mouse Dynamics:** Real users have curved mouse paths with variable velocity. Bots often "teleport" or move in perfect straight lines.
*   **Keystroke Dynamics:** Analysis of "flight time" (time between keys) and "dwell time" (time key is pressed). Bots have uniform distribution; humans have distinct rhythms.
*   **Touch Events:** On mobile, the surface area of the touch and the pressure sensor data are analyzed.

### Navigation Patterns
*   **DOM Interaction:** Checking if the client interacts with invisible elements (honeypots) or fails to render specific CSS/Canvas elements correctly.
*   **Resource Loading:** Headless browsers often skip loading images, fonts, or ads to save bandwidth. Platforms detect these missing resource requests.

## 3. Graph & Social Analysis

### Interaction Graphs
*   **Star Topology:** A "Main" account receiving likes/retweets from many unconnected "Satellite" accounts creates a distinct star pattern in the interaction graph.
*   **Synchronized Action:** If 50 accounts perform an action (Like/RT) within a tight time window (e.g., 1 second), it triggers "Coordinated Inauthentic Behavior" (CIB) flags.

### Account Metadata
*   **Creation Clusters:** Accounts created at similar times, with similar username patterns (e.g., `Name123`, `Name124`), or using the same email domain provider are grouped.
*   **Profile Similarity:** Using perceptual hashing (pHash) to detect identical or slightly modified profile pictures across thousands of accounts.

## 4. Content Analysis

### Text & Link Patterns
*   **Fuzzy Hashing:** Algorithms like SimHash or MinHash detect near-duplicate text (spam templates) even if a few words are changed.
*   **URL Unshortening:** Platforms resolve shortened links to find the final destination. If many accounts link to the same domain, that domain is flagged.
*   **OCR & Vision:** Optical Character Recognition extracts text from images to detect spam embedded in visuals.
