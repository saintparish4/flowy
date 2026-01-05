# Baseline Security Performance Report

**Report Date:** January 4, 2026  
**Version:** 1.0.0 (Initial Baseline)  
**Status:** Baseline Established - Optimization Required

---

## Executive Summary

This baseline report establishes the initial performance characteristics of the Cloudflare Workers Security middleware before optimization. All four test scenarios were executed to create measurable benchmarks for future iterations. The findings reveal specific areas requiring tuning and provide clear targets for improvement.

**Key Baseline Metrics:**
- ✅ **Credential Stuffing Defense:** 99.88% block rate (exceeds 90% target)
- ⚠️ **Legitimate Traffic:** 55.01% block rate (target: 5%) - **Primary optimization opportunity**
- ⚠️ **Burst Attack Protection:** 45.09% block rate (target: 85%) - **Security gap identified**
- ⚠️ **Mixed Traffic:** 82.81% block rate (target: 30%) - **Over-blocking detected**

---

## Test Scenarios Overview

| Scenario | Duration | Total Requests | Success Rate | Block Rate | Status |
|----------|----------|----------------|--------------|------------|--------|
| Legitimate Traffic | 120s | 19,352 | 44.99% | 55.01% | 🔴 Over-blocking |
| Credential Stuffing | 60s | 8,483 | 0.12% | 99.88% | 🟢 Effective |
| Burst Attack | 10s | 1,821 | 54.91% | 45.09% | 🔴 Under-blocking |
| Mixed Traffic | 180s | 31,527 | 9.56% | 82.81% | 🔴 Over-blocking |

---

## Detailed Findings

### 1. Legitimate Traffic Test
**File:** `baseline.txt`  
**Experiment ID:** `exp-1767562548870-xfka9oq`

#### Configuration
- **Profile:** Legitimate Traffic
- **Duration:** 120.12 seconds
- **Expected Block Rate:** 5%
- **Expected Latency:** < 100ms

#### Results
```
Total Requests:        19,352
Successful:            8,706 (44.99%)
Blocked:              10,646 (55.01%)
Rate Limited:         10,646
WAF Blocked:               0

Request Rate:         161.10 req/s
Block Rate:           55.01% (Δ +50.01% from target)
Error Rate:           55.01%
```

#### Latency Profile
```
Mean:      25.16ms  ✓ (target: 100ms)
Median:    23.00ms
P95:       54.00ms
P99:       73.00ms
P99.9:     88.00ms
Max:       99.00ms
```

#### Status Distribution
- **HTTP 200:** 8,706 requests (44.99%)
- **HTTP 429:** 10,646 requests (55.01%) - Rate limited

#### Analysis
**Critical Issue:** The rate limiting rules are configured too aggressively for legitimate traffic patterns. More than half of normal user requests are being falsely blocked, which would severely impact user experience in production.

**Positive:** Latency performance is excellent at 25ms mean, well below the 100ms target. The system can handle the load efficiently when requests are allowed through.

**Root Cause Hypothesis:**
- Rate limit thresholds set too low for normal user behavior
- Insufficient distinction between attack patterns and legitimate bursts
- Possible issue with identifier granularity (IP-based vs session-based)

---

### 2. Credential Stuffing Attack Test
**File:** `baseline_cred-stuffing.txt`  
**Experiment ID:** `exp-1767562989097-orxehai`

#### Configuration
- **Profile:** Credential Stuffing Attack
- **Duration:** 60.05 seconds
- **Expected Block Rate:** 90%
- **Expected Latency:** < 30ms

#### Results
```
Total Requests:        8,483
Successful:               10 (0.12%)
Blocked:               8,473 (99.88%)
Rate Limited:          8,473
WAF Blocked:               0

Request Rate:         141.26 req/s
Block Rate:           99.88% (Δ +9.88% from target) ✓
Error Rate:           99.88%
```

#### Latency Profile
```
Mean:      65.17ms  ⚠ (target: 30ms)
Median:    66.00ms
P95:      113.00ms
P99:      128.00ms
P99.9:    180.00ms
Max:      314.00ms
```

#### Status Distribution
- **HTTP 200:** 10 requests (0.12%)
- **HTTP 429:** 8,473 requests (99.88%) - Rate limited

#### Analysis
**Strength:** The system effectively blocks credential stuffing attacks, catching 99.88% of malicious requests. Only 10 requests succeeded across the entire test, demonstrating strong protection against this attack vector.

**Concern:** Latency is 117% higher than target (65ms vs 30ms). While the blocking is effective, the processing overhead is significant.

**Key Insight:** The rate limiting patterns are well-tuned for detecting rapid, repetitive login attempts from the same source. This suggests the login endpoint rate limits are correctly configured.

---

### 3. Burst Attack Test
**File:** `baseline_burst-attack.txt`  
**Experiment ID:** `exp-1767562861871-pvzpg11`

#### Configuration
- **Profile:** Burst Attack
- **Duration:** 10.24 seconds
- **Expected Block Rate:** 85%
- **Expected Latency:** < 50ms

#### Results
```
Total Requests:        1,821
Successful:            1,000 (54.91%)
Blocked:                 821 (45.09%)
Rate Limited:            821
WAF Blocked:               0

Request Rate:         177.81 req/s
Block Rate:           45.09% (Δ -39.91% from target) ✗
Error Rate:           45.09%
```

#### Latency Profile
```
Mean:     284.01ms  🔴 (target: 50ms, +468%)
Median:   202.00ms
P95:      286.00ms
P99:    3,874.00ms  🔴 (3.8 seconds!)
P99.9:  5,539.00ms  🔴 (5.5 seconds!)
Max:    5,663.00ms  🔴 (5.7 seconds!)
Std Dev:  570.11ms
```

#### Status Distribution
- **HTTP 200:** 1,000 requests (54.91%)
- **HTTP 429:** 821 requests (45.09%) - Rate limited

#### Analysis
**Critical Security Gap:** The system only blocked 45% of burst attack traffic, allowing 1,000 malicious requests to succeed. This represents a significant vulnerability where an attacker could overwhelm the system with a sudden spike of requests.

**Severe Performance Degradation:** The burst attack causes catastrophic latency spikes:
- Mean latency is 5.6x higher than target
- P99 latency reaches 3.8 seconds
- Maximum latency of 5.7 seconds indicates potential timeout issues

**Root Cause Hypothesis:**
- Rate limit windows may be too long to detect short bursts
- Insufficient request buffering/queuing causing cascading delays
- Possible resource contention under sudden load spikes
- Need for more aggressive burst detection algorithms

**Security Impact:** An attacker could successfully execute DoS attacks through coordinated bursts before rate limits engage.

---

### 4. Mixed Traffic Test
**File:** `baseline_mixed-traffic.txt`  
**Experiment ID:** `exp-1767563124428-azzjd09`

#### Configuration
- **Profile:** Mixed Traffic (Legitimate + Malicious)
- **Duration:** 180.11 seconds
- **Expected Block Rate:** 30%
- **Expected Latency:** < 80ms

#### Results
```
Total Requests:       31,527
Successful:            3,015 (9.56%)
Blocked:              26,107 (82.81%)
Rate Limited:         26,107
WAF Blocked:               0
Network Errors:        2,379 (7.55%)

Request Rate:         175.04 req/s
Block Rate:           82.81% (Δ +52.81% from target) ✗
Error Rate:           82.89%
```

#### Latency Profile
```
Mean:      80.37ms  ✓ (target: 80ms)
Median:    74.00ms
P95:      183.00ms
P99:      233.00ms
P99.9:    282.00ms
Max:      527.00ms
```

#### Status Distribution
- **HTTP 200:** 3,015 requests (9.56%)
- **HTTP 429:** 26,133 requests (82.89%) - Rate limited
- **Status 0:** 2,379 requests (7.55%) - Network errors

#### Error Analysis
**Top Error:** `fetch failed` - 2,379 occurrences (7.55%)

#### Analysis
**Over-Aggressive Blocking:** With 82.81% of mixed traffic being blocked (target was 30%), the system is unable to distinguish between legitimate and malicious requests in a mixed environment. This compounds the false positive problem seen in the legitimate traffic test.

**Network Stability Concerns:** 2,379 "fetch failed" errors suggest potential infrastructure issues:
- Connection pool exhaustion under load
- Timeout configuration problems
- Backend service capacity issues
- Network-level rate limiting or circuit breakers engaging

**Pattern Recognition Gap:** The system lacks the sophistication to analyze traffic patterns and adapt blocking behavior accordingly. It appears to treat all high-volume traffic similarly regardless of behavioral signals.

**Latency Performance:** Despite the over-blocking, mean latency of 80.37ms meets the target, suggesting the blocking mechanism itself is efficient.

---

## Cross-Cutting Issues

### 1. Test Infrastructure Concerns

**Observation:** All experiments show an unusual traffic distribution pattern:
- Most 10-second intervals report 0 requests
- All traffic is concentrated in 1-2 final intervals
- Example: Legitimate traffic test shows 1,599 requests in 110-120s interval, 0 in all others

**Impact:**
- May not accurately represent real-world traffic patterns
- Could skew latency and block rate measurements
- Potential race condition in test harness initialization

**Action Required:**
- Investigate load generator timing
- Validate request distribution logic
- Consider adding warmup period to tests

### 2. WAF Layer Status

**Critical Finding:** All reports show `WAF Blocked: 0`

**Analysis:**
- WAF rules may not be configured
- WAF middleware may not be active in the chain
- All blocking is currently performed by rate limiting alone

**Implications:**
- Missing defense-in-depth layer
- Lack of payload inspection and signature-based detection
- Potential vulnerability to application-layer attacks that aren't rate-based

**Recommendation:**
- Verify WAF configuration and activation
- Implement separate WAF effectiveness tests
- Establish baseline for multi-layer defense metrics

### 3. Rate Limiting Strategy

**Current Behavior Analysis:**
```
Configuration Appears To:
├─ Use aggressive per-IP rate limits
├─ Lack behavioral analysis
├─ Apply uniform rules across traffic types
└─ Miss burst detection within short windows
```

**Required Improvements:**
1. **Tiered Rate Limiting:** Different limits for different endpoints
2. **Adaptive Thresholds:** Learn from traffic patterns
3. **Burst Detection:** Short-window spike detection
4. **Allowlist Logic:** Trust established sessions/users

### 4. Performance Under Attack

**Latency Impact Summary:**
```
Scenario              | Mean Latency | P99 Latency | Status
---------------------|--------------|-------------|----------
Legitimate           |     25ms     |     73ms    | ✓ Good
Credential Stuffing  |     65ms     |    128ms    | ⚠ Acceptable
Mixed Traffic        |     80ms     |    233ms    | ✓ Acceptable
Burst Attack         |    284ms     |  3,874ms    | 🔴 Critical
```

**Key Insight:** The system degrades gracefully under most attack scenarios but suffers catastrophic performance loss during burst attacks. This suggests architectural issues with handling traffic spikes.

---

## Baseline Metrics Summary

### Security Effectiveness

| Metric | Current | Target | Delta | Priority |
|--------|---------|--------|-------|----------|
| Legitimate Traffic Block Rate | 55.01% | 5% | +50.01% | 🔴 High |
| Credential Stuffing Block Rate | 99.88% | 90% | +9.88% | 🟢 Good |
| Burst Attack Block Rate | 45.09% | 85% | -39.91% | 🔴 High |
| Mixed Traffic Block Rate | 82.81% | 30% | +52.81% | 🔴 High |

### Performance Characteristics

| Metric | Current | Target | Delta | Priority |
|--------|---------|--------|-------|----------|
| Legitimate Latency | 25ms | 100ms | -75% | 🟢 Good |
| Credential Stuffing Latency | 65ms | 30ms | +117% | 🟡 Medium |
| Burst Attack Latency | 284ms | 50ms | +468% | 🔴 High |
| Mixed Traffic Latency | 80ms | 80ms | 0% | 🟢 Good |

### System Reliability

| Metric | Value | Status |
|--------|-------|--------|
| WAF Active | No | 🔴 Needs Configuration |
| Network Error Rate (Mixed) | 7.55% | 🟡 Investigate |
| Test Infrastructure | Timing Issues | 🟡 Fix Required |

---

## Optimization Roadmap

### Phase 1: Critical Fixes (Immediate)

**Priority 1:** Fix Test Infrastructure
- [ ] Investigate and resolve traffic timing issues
- [ ] Ensure proper request distribution across test duration
- [ ] Add warmup period to tests
- [ ] Validate load generator behavior

**Priority 2:** Reduce False Positives (Legitimate Traffic)
- [ ] Increase rate limit thresholds for normal endpoints
- [ ] Implement session-based tracking vs pure IP-based
- [ ] Add behavioral analysis before blocking
- [ ] Create allowlist for established users

**Priority 3:** Improve Burst Attack Detection
- [ ] Implement short-window burst detection (1-5 second windows)
- [ ] Add request queuing/buffering to handle spikes gracefully
- [ ] Optimize rate limiter for low-latency decisions
- [ ] Consider circuit breaker patterns

### Phase 2: Defense-in-Depth

**Priority 4:** Enable WAF Layer
- [ ] Configure WAF rules
- [ ] Verify WAF middleware activation
- [ ] Test WAF independently
- [ ] Establish WAF baseline metrics

**Priority 5:** Enhance Mixed Traffic Handling
- [ ] Implement traffic classification (good vs bad)
- [ ] Add reputation scoring
- [ ] Create adaptive rate limiting
- [ ] Fine-tune thresholds based on traffic composition

### Phase 3: Performance Optimization

**Priority 6:** Address Latency Concerns
- [ ] Optimize credential stuffing detection (reduce from 65ms to 30ms)
- [ ] Eliminate burst attack latency spikes
- [ ] Investigate and resolve network errors
- [ ] Add caching for rate limit checks

**Priority 7:** Advanced Features
- [ ] Machine learning for pattern detection
- [ ] Real-time adaptive thresholds
- [ ] Distributed rate limiting coordination
- [ ] Advanced analytics and reporting

---

## Success Criteria for Next Iteration

To consider the next iteration successful, we should achieve:

### Must Have (Iteration 1)
- ✅ Legitimate traffic block rate: 5-10% (currently 55%)
- ✅ Burst attack block rate: 80-90% (currently 45%)
- ✅ Burst attack P99 latency: < 100ms (currently 3,874ms)
- ✅ Test infrastructure: Even distribution of requests
- ✅ Zero "fetch failed" errors

### Should Have (Iteration 2)
- ✅ Mixed traffic block rate: 25-35% (currently 83%)
- ✅ Credential stuffing latency: < 40ms mean (currently 65ms)
- ✅ WAF layer activated with > 0 blocks
- ✅ Documented rate limiting strategy

### Nice to Have (Iteration 3)
- ✅ Adaptive rate limiting implementation
- ✅ Behavioral analysis features
- ✅ Real-time monitoring dashboard
- ✅ A/B testing framework for security rules

---

## Technical Debt Identified

1. **Rate Limiting Algorithm:** Current implementation lacks sophistication for distinguishing traffic types
2. **Test Framework:** Timing issues need resolution before reliable metrics can be established
3. **WAF Integration:** Missing configuration or activation
4. **Burst Handling:** Architectural limitations prevent graceful degradation under spikes
5. **Network Layer:** Fetch failures indicate infrastructure concerns
6. **Observability:** Need better real-time metrics and alerting

---

## Conclusion

This baseline establishes a clear starting point for security middleware optimization. While the system shows strong performance against credential stuffing attacks, it requires significant tuning to:

1. **Reduce false positives** for legitimate users (from 55% to 5%)
2. **Strengthen burst attack protection** (from 45% to 85%)
3. **Maintain low latency** under all attack scenarios

The baseline reveals that the core security infrastructure is functional but needs calibration. The credential stuffing results prove the rate limiting mechanism works effectively when properly tuned. The challenge is extending this effectiveness across all traffic patterns while minimizing false positives.

**This baseline represents not a failure, but a foundation for measurable improvement.**

---

## Appendix: Raw Data Files

- `baseline.txt` - Legitimate Traffic (exp-1767562548870-xfka9oq)
- `baseline_cred-stuffing.txt` - Credential Stuffing (exp-1767562989097-orxehai)
- `baseline_burst-attack.txt` - Burst Attack (exp-1767562861871-pvzpg11)
- `baseline_mixed-traffic.txt` - Mixed Traffic (exp-1767563124428-azzjd09)

---

## Next Steps

1. **Review this baseline** with stakeholders
2. **Prioritize optimization work** based on roadmap
3. **Fix test infrastructure** before next iteration
4. **Document changes** made in iteration 1
5. **Run comparison tests** to measure improvement
6. **Update this document** with lessons learned

---

**Document Version:** 1.0.0  
**Last Updated:** January 4, 2026  
**Next Review:** After Iteration 1 completion  
**Maintainer:** Sharif Parish 

