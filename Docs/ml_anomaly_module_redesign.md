# Machine Learning Anomaly Detection Module Redesign Specification

## Purpose & Executive Summary

This document defines the architectural, mathematical, and methodological redesign of `core/ml_anomaly.py` for the Passive Network Forensic Framework.

The primary objective is to harden the unsupervised machine learning layer so that its research claims match its concrete implementation. We replace ad-hoc batch min-max normalization with the genuine **Liu et al. (ICDM 2008)** Isolation Forest anomaly score, eliminate circular feature leakage from the deterministic scoring engine, introduce explicit baseline requirements, and clearly distinguish **descriptive population deviation** from causal model attribution.

---

## 1. Separation of Concerns: The Core Architectural Doctrine

The framework maintains a strict boundary between deterministic cryptographic compliance and unsupervised anomaly detection:

> **"Our deterministic rule engine establishes cryptographic compliance; Isolation Forest is a secondary unsupervised layer that identifies sessions whose observable behavior is unusual relative to the analyzed population."**

```text
                               SESSION EVIDENCE
                                      │
              ┌───────────────────────┴───────────────────────┐
              ▼                                               ▼
   RAW OBSERVABLE TELEMETRY                       EXPLICIT PROTOCOL ARTIFACTS
  (12 Raw Telemetry Features)                     (Handshake, Certs, Commands)
              │                                               │
              ▼                                               ▼
       ISOLATION FOREST                           DETERMINISTIC RULE ENGINE
     (Liu et al. ICDM 2008)                        (NIST SP 800-52r2, RFCs)
              │                                               │
              ├──► Liu Anomaly Score s(x, n)                  ├──► Strict RFC Violations
              ├──► Threshold Check (s ≥ 0.65)                 ├──► Domain Component Scores
              └──► Unusual Feature Deviations                 └──► Posture Score & Risk Tier
                   (Descriptive Z-Scores)                          (0–100 / CRITICAL–LOW)
```

### Key Distinctions

| Characteristic | Deterministic Rule Engine & Scorer | Unsupervised Isolation Forest |
| :--- | :--- | :--- |
| **Question Answered** | *"Is this session compliant with RFCs & NIST standards?"* | *"Does this session look unusual relative to peer sessions?"* |
| **Ground Truth** | Authoritative security standards (RFC 9325, 8314, NIST 800-52r2) | Reference session population (current capture or baseline corpus) |
| **Output Type** | Posture Score (0–100) & Risk Tier (CRITICAL–LOW) | Anomaly Score $s(x, n) \in (0, 1)$ & Binary Anomaly Flag |
| **Override Authority** | **Authoritative**: governs final forensic posture | **Advisory**: flags outliers for forensic inspection; never mutates compliance scores |
| **Failure Mode** | Inconclusive if packet truncated/missing | `INSUFFICIENT_BASELINE` if session count too small (< 5) |

---

## 2. Mathematical Formulation: Liu et al. (2008) vs. Scikit-Learn

### 2.1 The Liu et al. Formulation

In the seminal paper (*Liu, Ting, Zhou, "Isolation Forest", IEEE ICDM 2008*), an ensemble of Isolation Trees ($iTrees$) isolates instances by randomly selecting a feature and randomly selecting a split value between the minimum and maximum values of the selected feature.

Since anomalies are few and have distinct attribute values, they are isolated closer to the root of an $iTree$.

The anomaly score $s(x, n)$ for an instance $x$ given a dataset of $n$ instances is defined as:

$$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$

Where:
- $h(x)$ is the path length of instance $x$ in an $iTree$ (number of edges traversed from root to terminating leaf).
- $E(h(x))$ is the expected (average) path length over an ensemble of $iTrees$.
- $c(n)$ is the average path length of unsuccessful searches in a Binary Search Tree (BST) built from $n$ instances:

$$c(n) = 2 \ln(n - 1) + \xi - \frac{2(n - 1)}{n}$$

Here $\xi \approx 0.5772156649$ (Euler-Mascheroni constant).

### 2.2 Interpretation of the Liu et al. Score

Because $E(h(x)) \ge 0$ and $c(n) > 0$, the anomaly score is bounded: $s(x, n) \in (0, 1)$.

1. **If $E(h(x)) \to 0$**: The instance is isolated almost immediately at the top of the trees.
   $$s(x, n) \to 2^0 = 1.0 \implies \text{Definite anomaly}$$
2. **If $E(h(x)) \to n - 1$**: The instance requires maximal partitioning down to individual nodes.
   $$s(x, n) \to 0.0 \implies \text{Definite normal (inlier)}$$
3. **If $E(h(x)) \approx c(n)$**: The instance requires the same average depth as a random node in a BST.
   $$s(x, n) \approx 2^{-1} = 0.5 \implies \text{No distinct anomaly pattern}$$

The project synopsis designates $s(x, n) \ge 0.65$ as the threshold for flagging a session for detailed forensic review.

### 2.3 The Flaw in Previous Implementation: Batch Min-Max Normalization

Scikit-learn's `IsolationForest.score_samples(X)` calculates:

$$\text{score\_samples}(X) = - 2^{-\frac{E(h(x))}{c(n)}} = - s(x, n)$$

(where more negative values indicate greater anomaly).

The previous codebase performed an ad-hoc batch min-max normalization:

$$\text{norm\_score} = 1.0 - \frac{\text{raw} - \min(\text{raw})}{\max(\text{raw}) - \min(\text{raw})}$$

This introduced severe methodological issues:
- If a capture consisted of 100 perfectly clean, identical sessions, the tiny random variation in tree splits would force one session to score $1.0$ (false alarm) and another to score $0.0$.
- If a capture consisted of 100 uniformly malicious sessions, the scores would still be stretched across $[0, 1]$, masking widespread intrusion.
- The fixed threshold $0.65$ lost its mathematical meaning.

### 2.4 The Redesigned Scoring Engine

In the redesigned module, we eliminate batch min-max normalization entirely:

$$s(x, n) = - \text{model.score\_samples}(X)$$

This directly recovers the true Liu et al. $s(x, n) \in (0, 1)$ without distortion.

---

## 3. Feature Engineering: Eliminating Derived Score Leakage

### 3.1 The Leakage Problem

In the legacy implementation, the feature vector included:
- Feature 9: `posture_score / 100.0`
- Feature 10: `len(violations)`

This caused severe data leakage: the unsupervised model was fed the final conclusions of the deterministic rule engine and posture scorer. As a result, the model was simply learning "low posture score = anomaly", demonstrating zero independent forensic value.

### 3.2 The Redesigned 12-Dimensional Raw Feature Vector

The redesigned feature extractor consumes **strictly raw observable network, cryptographic, and session attributes**:

| Index | Feature Name | Description | Encoding / Normalization |
| :---: | :--- | :--- | :--- |
| **0** | `tls_version` | Negotiated or offered TLS record/handshake version | Ordinal: SSLv2=0, SSLv3=1, TLS 1.0=2, TLS 1.1=3, TLS 1.2=4, TLS 1.3=5 |
| **1** | `channel_type` | Outer transport security mode | Ordinal: Plaintext=0, STARTTLS=1, Implicit TLS=2 |
| **2** | `starttls_status` | Application protocol upgrade state machine outcome | Ordinal: Stripped=0, Possible Stripping=0, Failed=1, Inconclusive=2, None=2, Advertised=3, Requested=4, Negotiated=5 |
| **3** | `key_exchange` | Key establishment algorithm family | Ordinal: RSA=0, DHE=1, ECDHE=2 |
| **4** | `forward_secrecy` | Perfect forward secrecy capability | Binary flag: $1.0$ if ECDHE or DHE, else $0.0$ |
| **5** | `buffer_injection` | Cleartext command pipelining / buffer injection | Binary flag: $1.0$ if observed before TLS record layer, else $0.0$ |
| **6** | `cert_validity` | X.509 certificate temporal and trust state | Ordinal: Unknown=0, Expired/Invalid=1, Self-signed=2, Valid=3 |
| **7** | `key_length_norm` | Asymmetric key size normalized | Continuous: $\min(1.0, \text{key\_length\_bits} / 4096.0)$ |
| **8** | `weak_sig_algo` | Deprecated digest in certificate signature | Binary flag: $1.0$ if MD5 or SHA-1 detected, else $0.0$ |
| **9** | `sni_present` | Server Name Indication extension present | Binary flag: $1.0$ if SNI extension observed in ClientHello, else $0.0$ *(replaces leaked posture score)* |
| **10** | `bytes_pre_tls_norm` | Volume of cleartext bytes preceding TLS records | Continuous: $\min(1.0, \log_{10}(\text{bytes\_pre\_tls} + 1) / 4.0)$ *(replaces leaked violation count)* |
| **11** | `byte_count_norm` | Total TCP flow byte volume log-normalized | Continuous: $\min(1.0, \log_{10}(\text{byte\_count} + 1) / 7.0)$ |

Zero derived scores, zero rule outputs. Every feature is a direct physical or cryptographic property of the network session.

---

## 4. Population Baseline and Contamination Semantics

### 4.1 Capture-Relative vs Reference Baseline

An unsupervised model trained on the sessions within a single PCAP answers:
> *"Is this session unusual relative to the other sessions captured in this file?"*

It does **not** know whether the traffic is secure or malicious in absolute terms.

### 4.2 Minimum Baseline Session Guard (`INSUFFICIENT_BASELINE`)

Isolation Forest constructs random partitions of the feature space. When $n < 5$, $c(n)$ lacks statistical stability, and clusters cannot be formed.

- **Previous behavior**: For small captures, the module returned `is_anomalous = False`, falsely implying the sessions were certified as normal.
- **Redesigned behavior**: If $n < \text{min\_baseline\_sessions}$ (default 5):
  - `anomaly_status = "INSUFFICIENT_BASELINE"`
  - `is_anomalous = False`
  - `anomaly_score = None`
  - `anomaly_features = {}`
  - Diagnostics clearly record that an unsupervised baseline could not be established due to small sample size.

### 4.3 Configurable Contamination

The expected proportion of outliers is governed by `MLSettings.contamination` (default $0.05$). Rather than hardcoding $0.15$, the parameter is propagated through `AnalysisConfig` and can be adjusted based on enterprise traffic profiles.

---

## 5. Explanation Semantics: Population Deviation vs Model Attribution

When a session is flagged as anomalous ($s(x, n) \ge 0.65$), the system computes feature deviations:

$$z_{i, j} = \frac{|x_{i, j} - \mu_j|}{\sigma_j + 10^{-9}}$$

Where $\mu_j$ and $\sigma_j$ are the mean and standard deviation of feature $j$ across the capture population.

### Scientific Honesty in Labeling

- **Legacy Label**: *"Features responsible for the anomaly"* or *"ML Feature Drivers"*.
  *Problem*: This falsely implies tree-split causal attribution (such as TreeSHAP).
- **Redesigned Label**: **"Most Unusual Characteristics (Population Deviation)"** or **"Unusual Feature Deviations"**.
  *Reality*: This honestly informs the forensic analyst which observable parameters statistically diverged the furthest from the peer population in this capture.

---

## 6. Model Metadata and Forensic Auditability

Every ML execution registers complete execution metadata within the session stage results (`stage11_ml_anomaly`):

```json
{
  "model_family": "IsolationForest",
  "scoring_formula": "Liu et al. (ICDM 2008) s(x, n) = 2^(-E(h(x))/c(n))",
  "feature_version": "v2-raw-observable",
  "feature_names": [
    "tls_version", "channel_type", "starttls_status", "key_exchange",
    "forward_secrecy", "buffer_injection", "cert_validity", "key_length_norm",
    "weak_sig_algo", "sni_present", "bytes_pre_tls_norm", "byte_count_norm"
  ],
  "n_estimators": 100,
  "contamination": 0.05,
  "anomaly_threshold": 0.65,
  "min_baseline_sessions": 5,
  "baseline_mode": "capture_relative",
  "sessions_evaluated": 25,
  "anomalies_detected": 2,
  "random_state": 42
}
```

This guarantees complete forensic reproducibility and auditability for research evaluations and incident investigations.
