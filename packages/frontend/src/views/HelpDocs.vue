<template>
  <div class="help-docs">
    <div class="header">
      <h1>Random Sequencer - Help & Documentation</h1>
      <Button label="Back to App" icon="pi pi-arrow-left" @click="$emit('close')" class="p-button-text" />
    </div>

    <div class="content">
      <Card class="doc-card">
        <template #title>Overview</template>
        <template #content>
          <p>
            Professional token randomness analyzer for security researchers implementing <strong>NIST SP 800-90B</strong> (entropy estimation)
            and <strong>NIST SP 800-22</strong> (statistical randomness testing). Analyzes session tokens, CSRF tokens, API keys,
            and security-critical parameters using cryptographic-grade analysis.
          </p>
          <p>
            <strong>Key Standards Implemented:</strong>
          </p>
          <ul>
            <li><strong>NIST SP 800-22 (Statistical Test Suite):</strong> Frequency (Monobit), Runs, Block Frequency, Serial, Approximate Entropy, Cumulative Sums tests</li>
            <li><strong>NIST SP 800-90B (Entropy Estimation):</strong> Min-entropy, Shannon entropy, per-position min-entropy, effective security bits</li>
            <li><strong>Per-Token Analysis:</strong> Tests run individually per token and aggregated for statistical reliability</li>
          </ul>
          <p>
            <strong>Key Difference from Other Tools:</strong> Uses <strong>min-entropy</strong> (worst-case guessability) instead of
            just Shannon entropy (average case). Attackers exploit worst-case scenarios, not averages. Additionally, implements
            full NIST SP 800-22 randomness test suite on raw token strings (8-bit per character).
          </p>
        </template>
      </Card>

      <Card class="doc-card">
        <template #title>How It Works</template>
        <template #content>
          <ol>
            <li><strong>Configure Collection:</strong>
              <ul>
                <li>Paste HTTP request from Caido</li>
                <li>Specify token parameter name (or use "Show Fields" to preview)</li>
                <li>Set request count (default: 10, recommended: 1000+ for production)</li>
                <li><strong>Optional:</strong> Enable "Token Strength Analysis (slower)" checkbox for cryptographic entropy analysis</li>
                <li><strong>Optional:</strong> Configure rate limiting (requests/batch, delay, auto-retry)</li>
              </ul>
            </li>
            <li><strong>Request Repetition:</strong> The plugin sends the same HTTP request multiple times to collect unique tokens</li>
            <li><strong>Token Extraction:</strong> For each response, it extracts the specified parameter from:
              <ul>
                <li>JSON response bodies (nested keys supported)</li>
                <li>Set-Cookie headers</li>
                <li>URL-encoded responses</li>
                <li>HTML input fields, meta tags, and data attributes</li>
                <li>JavaScript variable assignments</li>
                <li>Custom HTTP headers</li>
              </ul>
            </li>
            <li><strong>Randomness Analysis (Always Computed):</strong>
              <ul>
                <li>NIST SP 800-22 statistical tests per token (Monobit, Runs, Block Frequency, Serial, Approximate Entropy, Cumulative Sums)</li>
                <li>Token Position Analysis on raw string (character-level entropy per position)</li>
                <li>Pass/fail rates and median p-values aggregated across all tokens</li>
                <li>Randomness verdict: "Looks Random", "Mostly Random", or "Shows Patterns"</li>
              </ul>
            </li>
            <li><strong>Token Strength Analysis (Only if Enabled):</strong>
              <ul>
                <li>Byte decoding (base64, base64url, hex detection)</li>
                <li>Min-entropy, Shannon entropy, per-position min-entropy calculations</li>
                <li>Effective security bits computation</li>
                <li>Chi-squared uniformity test, serial correlation, runs test, LZ compression analysis</li>
                <li>Collision and Hamming distance analysis</li>
                <li>Security rating: CRITICAL, WARNING, GOOD, or EXCELLENT</li>
                <li>Plain English verdict with "How to Fix" recommendations</li>
              </ul>
            </li>
            <li><strong>Results Display:</strong>
              <ul>
                <li>Randomness Summary (always shown)</li>
                <li>Token Position Analysis chart (always shown when ≥50 tokens)</li>
                <li>Token Strength Analysis card (only if enabled before collection)</li>
                <li>Export to CSV/JSON for sharing with development teams</li>
              </ul>
            </li>
          </ol>
        </template>
      </Card>

      <Card class="doc-card">
        <template #title>Understanding Results</template>
        <template #content>
          <p>
            Results are presented in plain English with clear verdicts and actionable recommendations for non-experts.
          </p>

          <h3>Main Results Display</h3>
          <ul>
            <li><strong>Security Verdict:</strong> Large, color-coded rating (CRITICAL, WARNING, GOOD, or EXCELLENT)</li>
            <li><strong>Plain English Explanation:</strong> What the rating means in simple terms</li>
            <li><strong>Key Problems Detected:</strong> Specific issues found in the tokens</li>
            <li><strong>Security Impact:</strong> What attackers could do with these weaknesses</li>
            <li><strong>How to Fix:</strong> Step-by-step recommendations to improve token security</li>
          </ul>

          <h3>Randomness Summary</h3>
          <p>
            Always displayed after token collection. Shows statistical randomness test results based on SP 800-22:
          </p>
          <ul>
            <li><strong>Overall Verdict:</strong> Looks Random, Mostly Random, or Shows Patterns</li>
            <li><strong>Suggestions:</strong> Actionable tips based on test results</li>
            <li><strong>Weak Positions:</strong> Character positions with biased or predictable values</li>
            <li><strong>View Randomness Details:</strong> Opens dialog with per-test charts and interpretations</li>
          </ul>

          <h3>Token Position Analysis (Raw String)</h3>
          <p>
            Appears on main page when 50+ tokens collected. Shows character-level entropy at each position:
          </p>
          <ul>
            <li><strong>🔴 Red bars:</strong> Low normalized entropy - predictable characters at this position</li>
            <li><strong>🟡 Yellow bars:</strong> Moderate entropy - could be improved</li>
            <li><strong>🟢 Green bars:</strong> High entropy - random at this position</li>
          </ul>
          <p>
            <strong>Tooltip:</strong> Hover over any bar to see normalized entropy (0-8), most common character, frequency, and coverage.
          </p>

          <h3>Token Strength Analysis (Optional)</h3>
          <p>
            Enable the <strong>"Token Strength Analysis (slower)"</strong> checkbox before collection to compute:
          </p>
          <ul>
            <li><strong>Effective Security Bits:</strong> Cryptographic strength based on min-entropy</li>
            <li><strong>Entropy Metrics:</strong> Shannon, min-entropy, per-position min-entropy</li>
            <li><strong>Statistical Tests:</strong> Chi-squared, serial correlation, runs test, LZ compression</li>
            <li><strong>Decoded Byte Analysis:</strong> Per-byte entropy after decoding (base64/hex)</li>
            <li><strong>Security Rating:</strong> CRITICAL, WARNING, GOOD, or EXCELLENT</li>
            <li><strong>Plain English Verdict:</strong> What attackers can do with these weaknesses</li>
            <li><strong>How to Fix:</strong> Step-by-step recommendations</li>
          </ul>
          <p>
            <strong>Performance:</strong> Heavy computations may take longer for large token counts (1000+).
            Skip this if you only need randomness testing.
          </p>

          <h3>View Technical Details (Token Strength Analysis)</h3>
          <p>
            Only appears when Token Strength Analysis was enabled during collection. Shows:
          </p>
          <ul>
            <li>All entropy measurements (Shannon, Min-Entropy, Per-Position Min-Entropy)</li>
            <li>Statistical randomness tests (Chi-Squared, Serial Correlation, Runs Test)</li>
            <li>Decoded Byte Position Analysis chart (base64/hex decoded entropy per byte)</li>
            <li>Collision analysis and Hamming distances</li>
            <li>Pattern detection results</li>
            <li>Bit-level and character distribution analysis</li>
          </ul>
        </template>
      </Card>

      <Card class="doc-card">
        <template #title>NIST SP 800-22 Randomness Tests (Detailed)</template>
        <template #content>
          <p>
            The Randomness Tests implement a subset of <strong>NIST Special Publication 800-22 Rev. 1a</strong>, the industry standard
            for testing random number generators. Tests run on the <strong>raw token string</strong> (8-bit per character) to detect
            non-random patterns, biases, and structure.
          </p>
          <p>
            <strong>Methodology:</strong> Each test is computed <strong>per token individually</strong>, then results are aggregated:
          </p>
          <ul>
            <li><strong>Applicable Count:</strong> Number of tokens that met test preconditions (e.g., minimum bit length)</li>
            <li><strong>Pass Rate:</strong> Percentage of applicable tokens with p-value ≥ α (default α = 0.01)</li>
            <li><strong>Median p-value:</strong> Median p-value across all applicable tokens</li>
            <li><strong>Pass/Fail Threshold:</strong> p ≥ 0.01 = Pass (α = 0.01 significance level)</li>
          </ul>

          <h3>1. Frequency (Monobit) Test</h3>
          <p><strong>Purpose:</strong> Detects global imbalance between 0s and 1s in the bit sequence.</p>
          <div class="formula">
            S_obs = |Σ(2×ε_i - 1)| / √n
          </div>
          <p>Where ε_i is the i-th bit, n is total bits. Under randomness, S_obs follows a standard normal distribution.</p>
          <div class="formula">
            p-value = erfc(S_obs / √2)
          </div>
          <p><strong>Interpretation:</strong></p>
          <ul>
            <li><strong>Pass (p ≥ 0.01):</strong> Equal distribution of 0s and 1s - no global bit bias</li>
            <li><strong>Fail (p &lt; 0.01):</strong> Significant imbalance suggests deterministic encoding, biased charset, or structured prefix/suffix</li>
          </ul>

          <h3>2. Runs Test</h3>
          <p><strong>Purpose:</strong> Checks if the number of runs (uninterrupted sequences of identical bits) is as expected for random data.</p>
          <div class="formula">
            V_obs = Σ r(k), where r(k) = 0 if ε_k = ε_(k+1), else 1
          </div>
          <p>Expected runs for random sequence: E[V] = 2nπ(1-π) + 1, where π = proportion of 1s.</p>
          <div class="formula">
            p-value = erfc(|V_obs - E[V]| / (2√2n × π(1-π)))
          </div>
          <p><strong>Interpretation:</strong></p>
          <ul>
            <li><strong>Pass:</strong> Expected number of runs - no unusual clustering or alternating patterns</li>
            <li><strong>Fail:</strong> Too many/few runs indicates repeating sequences, structured boundaries, or predictable transitions</li>
          </ul>

          <h3>3. Block Frequency Test (M=256)</h3>
          <p><strong>Purpose:</strong> Tests uniformity of 0s and 1s within fixed-size blocks (256 bits) to detect localized bias.</p>
          <div class="formula">
            χ² = 4M × Σ(π_i - 0.5)², where π_i = proportion of 1s in block i
          </div>
          <div class="formula">
            p-value = igamc(N/2, χ²/2)
          </div>
          <p>Where N is number of blocks, igamc is the incomplete gamma function.</p>
          <p><strong>Interpretation:</strong></p>
          <ul>
            <li><strong>Pass:</strong> Uniform bit distribution within blocks - no localized clustering</li>
            <li><strong>Fail:</strong> Block-level bias indicates structured segments, padding, or non-uniform character usage</li>
          </ul>

          <h3>4. Serial Test (m=2)</h3>
          <p><strong>Purpose:</strong> Tests whether all m-bit overlapping patterns appear with equal frequency (m=2 checks 00, 01, 10, 11).</p>
          <div class="formula">
            ψ²_m = (2^m / n) × Σ v_i² - n
          </div>
          <p>Where v_i is the count of each m-bit pattern.</p>
          <div class="formula">
            Δψ²_m = ψ²_m - ψ²_(m-1)
          </div>
          <div class="formula">
            p-value = igamc(2^(m-2), Δψ²_m / 2)
          </div>
          <p><strong>Interpretation:</strong></p>
          <ul>
            <li><strong>Pass:</strong> All 2-bit patterns appear equally - no sequential dependencies</li>
            <li><strong>Fail:</strong> Preference for certain bit pairs suggests sequential patterns, encoding artifacts (base64/hex), or state correlations</li>
          </ul>

          <h3>5. Approximate Entropy Test (m=2)</h3>
          <p><strong>Purpose:</strong> Measures local randomness by comparing frequencies of overlapping m-bit and (m+1)-bit patterns.</p>
          <div class="formula">
            ApEn(m) = Φ(m) - Φ(m+1)
          </div>
          <div class="formula">
            Φ(m) = Σ (C_i^m / n) × log(C_i^m / n)
          </div>
          <p>Where C_i^m is the count of m-bit pattern i.</p>
          <div class="formula">
            χ² = 2n × (log(2) - ApEn(m))
          </div>
          <div class="formula">
            p-value = igamc(2^(m-1), χ²/2)
          </div>
          <p><strong>Interpretation:</strong></p>
          <ul>
            <li><strong>Pass:</strong> High local entropy - neighboring bits show unpredictable variation</li>
            <li><strong>Fail:</strong> Low local entropy - adjacent bits are correlated (common in counters, timestamps, structured formats)</li>
          </ul>

          <h3>6. Cumulative Sums Test (Forward & Backward)</h3>
          <p><strong>Purpose:</strong> Detects cumulative deviation from expected 50/50 bit balance, testing both forward and backward directions.</p>
          <div class="formula">
            S_k = Σ(i=1 to k) X_i, where X_i = 2ε_i - 1
          </div>
          <p>Compute maximum cumulative sum: z = max(|S_k|) for k ∈ [1, n]</p>
          <div class="formula">
            p-value = Σ(k=⌊-nz+1⌋ to ⌊nz-1⌋) [Φ((4k+1)z/√n) - Φ((4k-1)z/√n)]
          </div>
          <p>Where Φ is the standard normal CDF. Test runs both forward and backward; minimum p-value is reported.</p>
          <p><strong>Interpretation:</strong></p>
          <ul>
            <li><strong>Pass:</strong> No cumulative drift - bits are well-distributed throughout token length</li>
            <li><strong>Fail:</strong> Cumulative drift indicates biased prefixes/suffixes or monotonic trends (e.g., incrementing values)</li>
          </ul>

          <h3>Understanding Pass Rates</h3>
          <table style="width: 100%; border-collapse: collapse; margin: 1rem 0;">
            <thead>
              <tr style="background: var(--surface-ground);">
                <th style="border: 1px solid var(--surface-border); padding: 0.5rem;">Pass Rate</th>
                <th style="border: 1px solid var(--surface-border); padding: 0.5rem;">Median p-value</th>
                <th style="border: 1px solid var(--surface-border); padding: 0.5rem;">Verdict</th>
                <th style="border: 1px solid var(--surface-border); padding: 0.5rem;">Meaning</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">≥95%</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">≥0.05</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">🟢 Pass</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">Consistent with random data</td>
              </tr>
              <tr>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">80-95%</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">0.01-0.05</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">🟡 Marginal</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">Slight deviations; retest with more samples</td>
              </tr>
              <tr>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">&lt;80%</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">&lt;0.01</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">🔴 Fail</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">Significant non-random structure detected</td>
              </tr>
            </tbody>
          </table>

          <h3>Best Practices</h3>
          <ul>
            <li><strong>Sample Size:</strong> Use 100-500+ tokens for reliable statistical results. Small samples (&lt;50) may give false positives/negatives.</li>
            <li><strong>Token Length:</strong> Tests require minimum bits. Very short tokens (&lt;100 bits) will show as "Not Applicable".</li>
            <li><strong>Interpretation:</strong> A single test failure may not be critical; look for patterns across multiple tests.</li>
            <li><strong>View Randomness Details:</strong> Click to see per-test p-value histograms and detailed interpretations.</li>
          </ul>
        </template>
      </Card>

      <Card class="doc-card">
        <template #title>NIST 800-90B Entropy Analysis</template>
        <template #content>
          <p>
            This plugin implements <strong>NIST Special Publication 800-90B</strong> entropy estimation for cryptographic random number generation assessment.
          </p>

          <h3>Primary Metrics</h3>

          <h4>1. Effective Security Bits (Primary Metric)</h4>
          <div class="formula">
            Effective bits = min(H_min, H_per_position, bits × H_min_per_bit)
          </div>
          <p><strong>Interpretation:</strong> Actual cryptographic strength. Minimum: <strong>128 bits</strong> for secure systems.</p>
          <ul>
            <li><strong>&lt; 64 bits:</strong> 🔴 CRITICAL - Cryptographically broken, brute-forceable</li>
            <li><strong>64-127 bits:</strong> 🟡 WARNING - Insufficient for modern cryptography</li>
            <li><strong>≥ 128 bits:</strong> 🟢 GOOD/EXCELLENT - Meets NIST recommendations</li>
          </ul>

          <h4>2. Min-Entropy (Worst-Case Guessability)</h4>
          <div class="formula">
            H_min = -log₂(max(p(x)))
          </div>
          <p>
            Where <code>max(p(x))</code> is the highest probability of any token value.
            <strong>This is the primary security metric</strong> because attackers exploit the most common token.
          </p>

          <h4>3. Shannon Entropy (Average Randomness)</h4>
          <div class="formula">
            H_shannon = -Σ p(x) · log₂(p(x))
          </div>
          <p>
            Measures average uncertainty. <strong>Informational only</strong> - not used for security rating.
            Can be misleading when values are slightly biased.
          </p>

          <h4>4. Per-Position Min-Entropy</h4>
          <p>
            For fixed-length tokens, calculates min-entropy at each character position independently,
            then sums them. Detects position-specific biases (e.g., first char always 'a').
          </p>

          <h3>Statistical Randomness Tests</h3>

          <h4>Chi-Squared Test (Bit Uniformity)</h4>
          <div class="formula">
            χ² = Σ((O - E)² / E)
          </div>
          <p>Tests if 0s and 1s are uniformly distributed. <strong>Pass:</strong> p-value ≥ 0.05</p>

          <h4>Serial Correlation (Bit Independence)</h4>
          <div class="formula">
            r = cov(X,Y) / (σ_X · σ_Y)
          </div>
          <p>Measures correlation between consecutive bits. <strong>Good:</strong> |r| ≤ 0.1</p>

          <h4>Runs Test (Pattern Detection)</h4>
          <p>Analyzes sequences of consecutive identical bits. <strong>Pass:</strong> p-value ≥ 0.05</p>

          <h4>LZ Compression (Structure Detection)</h4>
          <p>LZ78-style compression to detect patterns. <strong>Good:</strong> ratio &lt; 1.05</p>

          <h3>Why Min-Entropy Over Shannon?</h3>
          <div class="warning-box">
            <p><strong>Shannon entropy can be misleading for security!</strong></p>
            <p>
              <strong>Example:</strong> 1000 tokens where one value appears 100 times (10%), others once each:
            </p>
            <ul>
              <li><strong>Shannon entropy:</strong> ~9.5 bits (looks good!)</li>
              <li><strong>Min-entropy:</strong> ~3.3 bits (reveals the weakness)</li>
              <li><strong>Reality:</strong> Attacker has 10% chance guessing the common token</li>
            </ul>
            <p>
              <strong>NIST Guidance:</strong> "Min-entropy shall be used... Shannon entropy is inappropriate for
              security assessments as it represents average-case rather than worst-case."
            </p>
          </div>

          <h3>Quick Reference Table</h3>
          <table style="width: 100%; border-collapse: collapse; margin: 1rem 0;">
            <thead>
              <tr style="background: var(--surface-ground);">
                <th style="border: 1px solid var(--surface-border); padding: 0.5rem;">Metric</th>
                <th style="border: 1px solid var(--surface-border); padding: 0.5rem;">Good</th>
                <th style="border: 1px solid var(--surface-border); padding: 0.5rem;">Warning</th>
                <th style="border: 1px solid var(--surface-border); padding: 0.5rem;">Critical</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">Effective Security Bits</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">≥128</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">64-127</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">&lt;64</td>
              </tr>
              <tr>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">Duplicates</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">&lt;5%</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">5-10%</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">&gt;10%</td>
              </tr>
              <tr>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">Chi-Squared p-value</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">≥0.05</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">0.01-0.05</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">&lt;0.01</td>
              </tr>
              <tr>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">Serial Correlation</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">|r|≤0.1</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">0.1&lt;|r|≤0.3</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">|r|&gt;0.3</td>
              </tr>
              <tr>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">Runs Test p-value</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">≥0.05</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">0.01-0.05</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">&lt;0.01</td>
              </tr>
              <tr>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">LZ Compression</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">&lt;1.05</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">1.05-1.2</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">&gt;1.2</td>
              </tr>
            </tbody>
          </table>

          <h3>Why 1000+ Samples?</h3>
          <div class="info-box">
            <p>
              Statistical analysis requires large sample sizes to be reliable. With fewer samples:
            </p>
            <ul>
              <li>Entropy calculations may be skewed by coincidental character patterns</li>
              <li>Duplicate detection might miss patterns (e.g., 5 duplicates in 50 samples = 10%, but same 5 in 1000 = 0.5%)</li>
              <li>Sequential patterns may not be evident with small datasets</li>
              <li>Rare but critical security flaws could go undetected</li>
            </ul>
            <p>
              <strong>Best Practice:</strong> Use 1000-5000 samples for production security audits.
              Use 50-200 only for quick testing or when rate-limiting is a concern.
            </p>
          </div>

          <h3>Pattern Detection</h3>
          <ul>
            <li><strong>Sequential Patterns:</strong> Detects if tokens are incrementing numbers (e.g., 1, 2, 3, 4...)</li>
            <li><strong>Timestamps:</strong> Identifies Unix timestamps (10-13 digits between years 2000-2100)</li>
            <li><strong>Common Prefix/Suffix:</strong> Finds shared strings at the start or end of all tokens</li>
            <li><strong>Predictability Score (0-100):</strong> Higher = more predictable
              <ul>
                <li>+40 points if sequential</li>
                <li>+30 points if timestamp-based</li>
                <li>+20 points if &gt;10% duplicates</li>
                <li>+10 points if common prefix &gt;3 characters</li>
              </ul>
            </li>
          </ul>

          <h3>Character Analysis</h3>
          <ul>
            <li><strong>Charset:</strong> Unique characters used across all tokens</li>
            <li><strong>Character Type Distribution:</strong> Count of alphabetic, numeric, and special characters</li>
            <li><strong>Format Detection:</strong> Identifies if tokens are hexadecimal or Base64 encoded</li>
          </ul>

          <h3>Bit-Level Analysis</h3>
          <p>
            Beyond character-level entropy, the plugin analyzes the <em>binary representation</em> of tokens:
          </p>
          <ul>
            <li><strong>Total Bits:</strong> Number of binary bits in all tokens</li>
            <li><strong>Ones vs Zeros Count:</strong> Distribution of 1s and 0s in the binary representation</li>
            <li><strong>Bit Entropy:</strong> Should be close to 1.0 for truly random data
              <ul>
                <li>&lt; 0.9 = Biased bit distribution (warning sign)</li>
                <li>&gt; 0.99 = Excellent bit-level randomness</li>
              </ul>
            </li>
          </ul>
        </template>
      </Card>

      <Card class="doc-card">
        <template #title>Security Ratings</template>
        <template #content>
          <h3>Overall Rating</h3>
          <ul>
            <li><strong class="critical">CRITICAL:</strong> One or more serious issues detected. Tokens are predictable or reusable.</li>
            <li><strong class="warning">WARNING:</strong> Some concerns found. Review the warnings carefully.</li>
            <li><strong class="good">GOOD:</strong> No major issues, but not excellent. Could be improved.</li>
            <li><strong class="excellent">EXCELLENT:</strong> Strong randomness with at least 3 positive indicators.</li>
          </ul>

          <h3>Common Issues</h3>
          <ul>
            <li><strong>High Duplicate Percentage (&gt;10%):</strong> Tokens are being reused frequently</li>
            <li><strong>Sequential Patterns:</strong> Tokens increment predictably (e.g., counting numbers)</li>
            <li><strong>Timestamp-Based:</strong> Tokens are based on current time (easily guessable)</li>
            <li><strong>Low Entropy (&lt;3.0):</strong> Very few unique characters, highly repetitive</li>
            <li><strong>Low Bit Entropy (&lt;0.9):</strong> Biased binary representation</li>
            <li><strong>High Predictability Score (&gt;50/100):</strong> Multiple red flags combined</li>
          </ul>
        </template>
      </Card>

      <Card class="doc-card">
        <template #title>How to Use</template>
        <template #content>
          <ol>
            <li><strong>Paste HTTP Request:</strong> Copy a raw HTTP request from Caido</li>
            <li><strong>Specify Parameter Name:</strong> Enter the exact name of the token parameter (e.g., "csrf_token", "sessionId", "token")
              <div class="info-box">
                <strong>Response Viewer Feature:</strong> If you leave the parameter name empty and click "Show Fields",
                the plugin will send a test request and display the response in a dual-panel viewer:
                <ul>
                  <li><strong>Response Headers:</strong> View all HTTP headers including Set-Cookie headers</li>
                  <li><strong>Response Body:</strong> View the full response body (JSON, HTML, etc.)</li>
                </ul>
                <p>
                  The text is fully selectable - simply find the parameter name in the response (e.g., in Set-Cookie headers or JSON keys),
                  select it with your mouse, copy it (Ctrl+C), and paste it into the "Token Parameter Name" field.
                </p>
                <p>
                  <strong>Quick Select Buttons:</strong> If the plugin detects common parameters like <code>token</code>, <code>session</code>,
                  <code>csrf_token</code>, or <code>sessionId</code>, you'll see clickable buttons to auto-fill the parameter name.
                </p>
                <p>
                  <strong>Error Handling:</strong> If the request fails, you'll see:
                </p>
                <ul>
                  <li>A red error message banner showing the failure reason (e.g., "Failed to send request: OperationFailed", "Connection refused")</li>
                  <li>A "Collected Responses (1)" card will appear</li>
                  <li>Click the blue "View All Responses" button to see full error details including the request sent and error type</li>
                </ul>
                <p>
                  <strong>Common connection errors:</strong>
                </p>
                <ul>
                  <li><strong>Failed to connect / Connection refused:</strong> Wrong host, port, or server not running</li>
                  <li><strong>OperationFailed:</strong> Check URL protocol (http vs https) and network connectivity</li>
                  <li><strong>SSL/TLS errors:</strong> Certificate issues or protocol mismatch</li>
                </ul>
              </div>
            </li>
            <li><strong>Set Request Count:</strong> Choose how many requests to send
              <div class="warning-box">
                <strong>⚠️ Important:</strong> For reliable entropy and statistical analysis, use at least <strong>1000 samples</strong>.
                Smaller sample sizes (50-200) may give unreliable results and incorrect security ratings.
                The default is set low for testing, but production analysis should use 1000+ requests.
              </div>
              <div class="info-box">
                <strong>⚠️ Rate Limiting:</strong> Many applications have rate limits that may block excessive requests.
                <p><strong>How to identify rate limiting:</strong></p>
                <ul>
                  <li>Look for "Request Failed" errors in the red error message banner</li>
                  <li>Check "View All Responses" - you'll see error messages like "429 Too Many Requests" or "Rate limit exceeded"</li>
                  <li>Partial success (e.g., "850 of 1000 requests failed (15% success rate)")</li>
                  <li>Responses containing "throttle", "rate limit", or similar messages</li>
                </ul>
                <p><strong>How to work around rate limits:</strong></p>
                <ul>
                  <li><strong>Start with a small test</strong> (10-50 requests) to check if rate limiting exists</li>
                  <li><strong>Enable Rate Limiting</strong> - Use the built-in rate limiting feature (see below)</li>
                  <li><strong>Reduce request count:</strong> If you hit rate limits with 1000, try 100-500 instead</li>
                  <li><strong>Split into multiple sessions:</strong> Run 200 requests, wait, then run another 200, and combine exports</li>
                  <li><strong>Use different credentials:</strong> If testing with auth, try different accounts</li>
                </ul>
                <p>
                  <strong>Best Practice:</strong> Always start with 10-20 requests as a test run. If successful,
                  gradually increase (50 → 100 → 500 → 1000) until you find the optimal count that doesn't trigger rate limiting.
                </p>
              </div>
            </li>
            <li><strong>Configure Rate Limiting (Optional):</strong> Control request pacing to avoid overwhelming the server
              <div class="info-box">
                <p>
                  <strong>Enable Rate Limiting checkbox:</strong> Activates request throttling with configurable options
                </p>
                <h4>Basic Settings:</h4>
                <ul>
                  <li><strong>Requests per Batch:</strong> Number of requests to send before pausing (e.g., 10 means send 10, then wait)</li>
                  <li><strong>Delay Between Batches:</strong> Milliseconds to wait after each batch (e.g., 5000 = 5 seconds)</li>
                </ul>
                <h4>Auto-Retry on 429 (HTTP 429 = "Too Many Requests"):</h4>
                <ul>
                  <li><strong>Enable:</strong> Automatically retry failed requests when rate limited</li>
                  <li><strong>Max Retries:</strong> How many times to retry each failed request (1-10)</li>
                  <li><strong>Retry Delay:</strong> Initial wait time before first retry in milliseconds</li>
                  <li><strong>Backoff Multiplier:</strong> How much to increase delay on each retry (e.g., 2 means: 1st retry waits 1s, 2nd waits 2s, 3rd waits 4s)</li>
                </ul>
                <h4>Example Calculation:</h4>
                <p>
                  The plugin shows estimated time: <code>With 10 requests/batch and 5000ms delay, 100 total requests will take approximately 50 seconds</code>
                </p>
                <h4>How to Find Optimal Settings:</h4>
                <ol>
                  <li><strong>Start conservative:</strong> 10 requests/batch, 5000ms delay (5 seconds)</li>
                  <li><strong>Test with small count:</strong> Run 50 total requests and check "View All Responses"</li>
                  <li><strong>If no 429 errors:</strong> Increase batch size (e.g., 20 requests/batch) or reduce delay (e.g., 2000ms)</li>
                  <li><strong>If 429 errors occur:</strong> Reduce batch size (e.g., 5 requests/batch) or increase delay (e.g., 10000ms = 10 seconds)</li>
                  <li><strong>Enable auto-retry:</strong> Set max retries to 3, retry delay 1000ms, backoff 2x to automatically handle occasional rate limits</li>
                </ol>
                <h4>Understanding Rate Limits by Testing:</h4>
                <ul>
                  <li><strong>No rate limit:</strong> All requests succeed regardless of batch size/delay</li>
                  <li><strong>Soft rate limit:</strong> Occasional 429 errors → enable auto-retry, works fine</li>
                  <li><strong>Strict rate limit:</strong> Frequent 429 errors → reduce batch size, increase delay significantly</li>
                  <li><strong>Time-based window:</strong> If errors appear after N requests → that's your limit per time window</li>
                </ul>
                <p>
                  <strong>Pro Tip:</strong> Use "View All Responses" to see which request number started failing.
                  If requests 1-50 succeed but 51+ fail, the rate limit window is likely 50 requests per time period.
                </p>
              </div>
            </li>
            <li><strong>Start Collection:</strong> Click "Start Collection" and wait for analysis to complete</li>
            <li><strong>Review Results:</strong> Check the security rating, issues, and detailed statistics
              <ul>
                <li><strong>Request Failed:</strong> A red error banner appears if requests couldn't be completed. Click "View All Responses" to see detailed error information for each failed request</li>
                <li><strong>Parameter Not Found:</strong> The parameter name wasn't found in the response - double-check the spelling or use "Show Fields" to verify</li>
                <li><strong>High Duplicates:</strong> Even with good entropy, high duplicate percentages indicate tokens are being reused (critical security issue)</li>
                <li><strong>View All Responses:</strong> Click the blue button to inspect individual responses, tokens extracted, and any error messages</li>
              </ul>
            </li>
            <li><strong>Export Data:</strong> Download CSV or JSON for further analysis</li>
          </ol>

          <h3>Tips</h3>
          <ul>
            <li>Test different endpoints that generate tokens (login, password reset, API keys, etc.)</li>
            <li><strong>Start small, then scale up</strong> - Begin with 10-20 requests to test for rate limits before going to 1000+</li>
            <li><strong>Always use 1000+ samples for production security audits</strong> - but only if rate limits allow</li>
            <li><strong>Use "Show Fields" first</strong> - View the raw response to understand the format and verify connectivity before starting collection</li>
            <li><strong>Error messages are visible immediately</strong> - A red banner appears for connection errors, making it easy to debug issues</li>
            <li><strong>View All Responses</strong> - Monitor this dialog (blue button) to catch errors or rate limiting issues early</li>
            <li>Compare results across different applications to identify patterns</li>
            <li><strong>Green export buttons</strong> - Click "Export CSV" or "Export JSON" (green buttons in the top-right) to share findings with development teams</li>
            <li>If the initial request fails with connection errors, verify your host, port, and protocol (http vs https) before trying again</li>
          </ul>
        </template>
      </Card>

      <Card class="doc-card">
        <template #title>Dealing with Rate Limits</template>
        <template #content>
          <p>
            Rate limiting is one of the most common challenges when performing token analysis.
            This section explains how to identify and work around rate limits.
          </p>

          <h3>What is Rate Limiting?</h3>
          <p>
            Rate limiting is a security mechanism that restricts the number of requests a client can make
            within a specific time window (e.g., 100 requests per minute, 1000 per hour). This prevents
            abuse, DDoS attacks, and excessive resource consumption.
          </p>

          <h3>Signs You've Hit a Rate Limit</h3>
          <div class="warning-box">
            <ul>
              <li><strong>HTTP 429 "Too Many Requests"</strong> - Standard rate limit response</li>
              <li><strong>HTTP 403 Forbidden</strong> - Sometimes used for rate limiting</li>
              <li><strong>High failure rates</strong> - "850 of 1000 requests failed (15% success)"</li>
              <li><strong>Error messages in responses:</strong> "throttle", "rate limit exceeded", "please wait", "try again later"</li>
              <li><strong>Temporary blocks</strong> - First few requests succeed, then all fail</li>
              <li><strong>IP-based blocking</strong> - Requests fail with connection or timeout errors</li>
            </ul>
          </div>

          <h3>Step-by-Step: Finding Your Rate Limit</h3>
          <ol>
            <li><strong>Initial Test (10 requests):</strong> Start very small to verify the endpoint works</li>
            <li><strong>Check results:</strong> Click "View All Tokens" and verify all 10 succeeded</li>
            <li><strong>Double it (20 requests):</strong> If successful, try 20</li>
            <li><strong>Scale gradually:</strong> 50 → 100 → 200 → 500 → 1000</li>
            <li><strong>Stop when you hit failures:</strong> If 500 works but 1000 fails, your limit is around 500</li>
            <li><strong>Use 80% of limit:</strong> If limit is 500, use 400 to be safe (leave buffer for retries)</li>
          </ol>

          <h3>Strategies to Maximize Sample Size</h3>
          <div class="info-box">
            <h4>1. Use Built-in Rate Limiting Controls (Recommended)</h4>
            <p>The plugin includes a rate limiting feature that automatically handles request pacing:</p>
            <ul>
              <li><strong>Enable Rate Limiting</strong> checkbox in the Token Collection section</li>
              <li><strong>Configure batch size:</strong> Send N requests, then pause (e.g., 10 requests/batch)</li>
              <li><strong>Set delay:</strong> Wait time between batches in milliseconds (e.g., 5000ms = 5 seconds)</li>
              <li><strong>Auto-retry on 429:</strong> Automatically retry when rate limited with exponential backoff</li>
              <li><strong>View calculation:</strong> See estimated total time before starting collection</li>
            </ul>
            <p><strong>Example:</strong> Set to 10 requests/batch with 5000ms delay → sends 10 requests, waits 5 seconds, repeats. For 1000 requests, this takes ~8.5 minutes but avoids rate limiting.</p>

            <h4>2. Split Collection Sessions</h4>
            <p>Run multiple smaller collections and combine the results:</p>
            <ul>
              <li>Run 200 requests → Export JSON</li>
              <li>Wait 5-10 minutes</li>
              <li>Run another 200 requests → Export JSON</li>
              <li>Repeat until you have 1000+ samples</li>
              <li>Combine JSON exports for full analysis</li>
            </ul>

            <h4>3. Adjust Request Timing with Rate Limiting Feature</h4>
            <p>Use the rate limiting controls to fine-tune request pacing:</p>
            <ul>
              <li><strong>Conservative:</strong> 5 requests/batch, 10000ms delay (10 seconds between batches)</li>
              <li><strong>Moderate:</strong> 10 requests/batch, 5000ms delay (5 seconds between batches)</li>
              <li><strong>Aggressive:</strong> 20 requests/batch, 2000ms delay (2 seconds between batches)</li>
              <li><strong>Test incrementally:</strong> Start conservative, then increase if no 429 errors appear</li>
            </ul>

            <h4>4. Use Different IP Addresses or Sessions</h4>
            <ul>
              <li>If rate limiting is per-session, log out and back in between runs</li>
              <li>If rate limiting is per-IP, use different network connections (carefully, don't violate terms of service)</li>
              <li>For penetration testing with permission, coordinate with the application team to whitelist your IP</li>
            </ul>

            <h4>5. Work with Application Team</h4>
            <p>If you're testing your own application or have authorization:</p>
            <ul>
              <li>Request temporary rate limit increase for your test account/IP</li>
              <li>Use internal/staging environments with relaxed limits</li>
              <li>Ask for rate limit details (e.g., "100 per minute") to plan accordingly</li>
            </ul>
          </div>

          <h3>Balancing Sample Size vs Rate Limits</h3>
          <table style="width: 100%; border-collapse: collapse; margin: 1rem 0;">
            <thead>
              <tr style="background: var(--surface-ground);">
                <th style="border: 1px solid var(--surface-border); padding: 0.5rem; text-align: left;">Sample Count</th>
                <th style="border: 1px solid var(--surface-border); padding: 0.5rem; text-align: left;">Statistical Reliability</th>
                <th style="border: 1px solid var(--surface-border); padding: 0.5rem; text-align: left;">Use Case</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">10-50</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">❌ Very Low</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">Initial testing, rate limit discovery</td>
              </tr>
              <tr>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">100-200</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">⚠️ Low</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">Quick assessment, high rate limits</td>
              </tr>
              <tr>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">500-1000</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">✅ Good</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">Standard security audit</td>
              </tr>
              <tr>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">1000-5000</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">✅ Excellent</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">Production audit, no rate limits</td>
              </tr>
              <tr>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">5000+</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">✅ Optimal</td>
                <td style="border: 1px solid var(--surface-border); padding: 0.5rem;">Critical systems, compliance requirements</td>
              </tr>
            </tbody>
          </table>

          <h3>Real-World Example</h3>
          <div class="example">
            <strong>Scenario:</strong> Testing a login endpoint<br><br>

            <strong>Attempt 1 (1000 requests, no rate limiting):</strong><br>
            Result: 950 failed - "429 Too Many Requests"<br>
            Conclusion: Rate limit hit<br><br>

            <strong>Attempt 2 (100 requests, no rate limiting):</strong><br>
            Result: All successful<br>
            Conclusion: Limit is above 100<br><br>

            <strong>Attempt 3 (500 requests, no rate limiting):</strong><br>
            Result: 450 successful, 50 failed<br>
            Conclusion: Limit is around 450/minute<br><br>

            <strong>Final Strategy (Using Built-in Rate Limiting):</strong><br>
            ✅ Enable Rate Limiting checkbox<br>
            ✅ Set 50 requests/batch, 60000ms delay (1 minute between batches)<br>
            ✅ Enable auto-retry on 429: max retries 3, retry delay 2000ms, backoff 2x<br>
            ✅ Run 1000 requests in a single collection<br>
            Result: Plugin automatically paces requests (50 every minute) + retries any 429 errors<br>
            Total time: ~20 minutes, but fully automated with 1000 clean samples!<br><br>

            <strong>Alternative (Manual Sessions):</strong><br>
            Run 400 requests → wait 1 minute → run 400 more → repeat<br>
            After 3 sessions, you have 1200 samples with no rate limit issues!
          </div>
        </template>
      </Card>

      <Card class="doc-card">
        <template #title>Example Scenarios</template>
        <template #content>
          <h3>Scenario 1: Session Token Analysis</h3>
          <div class="example">
            <strong>Input:</strong> Login endpoint that returns a session cookie<br>
            <strong>Parameter:</strong> "SESSIONID"<br>
            <strong>Result:</strong> 5% duplicates, entropy 4.8, no patterns<br>
            <strong>Rating:</strong> ✅ EXCELLENT - Tokens are secure
          </div>

          <h3>Scenario 2: CSRF Token Reuse</h3>
          <div class="example">
            <strong>Input:</strong> Page with CSRF protection<br>
            <strong>Parameter:</strong> "csrf_token"<br>
            <strong>Result:</strong> 85% duplicates, entropy 4.5<br>
            <strong>Rating:</strong> ❌ CRITICAL - High entropy BUT tokens are reused (insecure!)
          </div>

          <h3>Scenario 3: Timestamp-Based Tokens</h3>
          <div class="example">
            <strong>Input:</strong> API endpoint generating tokens<br>
            <strong>Parameter:</strong> "access_token"<br>
            <strong>Result:</strong> 0% duplicates, entropy 3.2, timestamp pattern detected<br>
            <strong>Rating:</strong> ❌ CRITICAL - Tokens are predictable (based on time)
          </div>

          <h3>Scenario 4: Sequential IDs</h3>
          <div class="example">
            <strong>Input:</strong> User registration endpoint<br>
            <strong>Parameter:</strong> "user_id"<br>
            <strong>Result:</strong> 0% duplicates, entropy 2.8, sequential pattern<br>
            <strong>Rating:</strong> ❌ CRITICAL - IDs increment (1, 2, 3, 4...), highly predictable
          </div>
        </template>
      </Card>

      <Card class="doc-card">
        <template #title>Technical Details</template>
        <template #content>
          <h3>Entropy Calculation</h3>
          <p>Shannon entropy is calculated by:</p>
          <ol>
            <li>Counting the frequency of each character across all tokens</li>
            <li>Computing probability: p(char) = count(char) / total_characters</li>
            <li>Applying the formula: H = -Σ(p(x) × log₂(p(x)))</li>
          </ol>

          <h3>Bit Entropy Calculation</h3>
          <ol>
            <li>Convert each character to its 8-bit binary representation</li>
            <li>Count total 1s and 0s across all bits</li>
            <li>Calculate probabilities: p(1) and p(0)</li>
            <li>Apply formula: H = -(p(1) × log₂(p(1)) + p(0) × log₂(p(0)))</li>
          </ol>

          <h3>Supported Token Locations</h3>
          <p>The plugin can extract tokens from:</p>
          <ul>
            <li>JSON: <code>{"token": "abc123"}</code> or nested <code>{"data": {"token": "abc123"}}</code></li>
            <li>Cookies: <code>Set-Cookie: token=abc123</code></li>
            <li>URL-encoded: <code>token=abc123&amp;other=value</code></li>
            <li>HTML inputs: <code>&lt;input name="token" value="abc123"&gt;</code></li>
            <li>Meta tags: <code>&lt;meta name="token" content="abc123"&gt;</code></li>
            <li>Data attributes: <code>&lt;div data-token="abc123"&gt;</code></li>
            <li>JavaScript: <code>var token = "abc123";</code></li>
            <li>Custom headers: Any header matching the parameter name</li>
          </ul>
        </template>
      </Card>
    </div>
  </div>
</template>

<script setup lang="ts">
import Card from "primevue/card";
import Button from "primevue/button";

defineEmits<{
  close: []
}>();
</script>

<style scoped>
.help-docs {
  max-width: 1000px;
  margin: 0 auto;
  padding: 2rem;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 2rem;
  border-bottom: 2px solid var(--surface-border);
  padding-bottom: 1rem;
}

.header h1 {
  margin: 0;
  font-size: 2rem;
  color: var(--text-color);
}

.content {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.doc-card {
  background: var(--surface-card);
}

.doc-card h3 {
  margin-top: 1.5rem;
  margin-bottom: 0.5rem;
  color: var(--primary-color);
  font-size: 1.2rem;
}

.doc-card h4 {
  margin-top: 1rem;
  margin-bottom: 0.5rem;
  color: var(--text-color);
  font-size: 1rem;
}

.doc-card ul, .doc-card ol {
  margin: 0.5rem 0;
  padding-left: 2rem;
}

.doc-card li {
  margin: 0.5rem 0;
  line-height: 1.6;
}

.doc-card p {
  line-height: 1.8;
  margin: 0.75rem 0;
}

.formula {
  background: var(--surface-ground);
  padding: 1rem;
  border-radius: 6px;
  font-family: 'Courier New', monospace;
  text-align: center;
  font-size: 1.2rem;
  margin: 1rem 0;
  border-left: 4px solid var(--primary-color);
}

.warning-box {
  background: rgba(255, 193, 7, 0.15);
  border-left: 4px solid #ffc107;
  padding: 1rem;
  border-radius: 6px;
  margin: 1rem 0;
  color: var(--text-color);
}

.warning-box p:first-child {
  font-weight: bold;
  color: var(--text-color);
  margin-top: 0;
}

.warning-box code {
  background: rgba(0, 0, 0, 0.2);
  padding: 2px 6px;
  border-radius: 3px;
  font-family: 'Courier New', monospace;
  color: var(--text-color);
}

.info-box {
  background: rgba(59, 130, 246, 0.15);
  border-left: 4px solid #3b82f6;
  padding: 1rem;
  border-radius: 6px;
  margin: 1rem 0;
  color: var(--text-color);
}

.info-box p:first-child {
  font-weight: bold;
  color: var(--text-color);
  margin-top: 0;
}

.info-box code {
  background: rgba(0, 0, 0, 0.2);
  padding: 2px 6px;
  border-radius: 3px;
  font-family: 'Courier New', monospace;
  color: var(--text-color);
}

.info-box ul {
  margin: 0.5rem 0;
  padding-left: 2rem;
}

.info-box li {
  margin: 0.3rem 0;
  line-height: 1.6;
}

.example {
  background: var(--surface-ground);
  padding: 1rem;
  border-radius: 6px;
  margin: 0.75rem 0;
  border-left: 4px solid var(--surface-border);
  font-family: 'Courier New', monospace;
  font-size: 0.9rem;
  line-height: 1.8;
}

.critical {
  color: #ef4444;
  font-weight: bold;
}

.warning {
  color: #f59e0b;
  font-weight: bold;
}

.good {
  color: #3b82f6;
  font-weight: bold;
}

.excellent {
  color: #10b981;
  font-weight: bold;
}

code {
  background: var(--surface-ground);
  padding: 2px 6px;
  border-radius: 3px;
  font-family: 'Courier New', monospace;
  font-size: 0.9em;
}
</style>
