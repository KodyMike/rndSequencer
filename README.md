# Caido Random Sequencer

A **NIST 800-90B compliant** token randomness analyzer for Caido. Assess cryptographic strength of session tokens, CSRF tokens, API keys, and security-critical parameters using professional entropy analysis.

## Features

### Token Analysis
- Multi-source extraction from URLs, form data, JSON, cookies, and HTTP headers
- **NIST 800-90B compliant entropy analysis** including:
  - Shannon entropy (average randomness)
  - Min-entropy (worst-case guessability)
  - Per-position min-entropy analysis
  - LZ compression-based entropy estimation
- Statistical randomness tests:
  - Chi-squared uniformity test
  - Serial correlation (bit independence)
  - Runs test (pattern detection)
- Collision and Hamming distance analysis
- Pattern detection for sequential numbers, timestamps, and common prefixes/suffixes
- Predictability scoring based on multiple factors

### Security Assessment
- Automated security rating (Critical, Warning, Good, Excellent)
- **Effective security bits calculation** (primary security metric)
- Character-level and bit-level entropy analysis
- Duplicate percentage tracking
- Comprehensive security recommendations based on NIST guidance

### User Interface
- Response viewer for inspecting raw HTTP responses
- Auto-detection of common token parameters
- Real-time error handling with clear messages
- Export to CSV and JSON formats
- Configurable rate limiting with auto-retry on HTTP 429
- Batch request control with customizable delays

## Installation

### From Release (Recommended)
1. Go to [GitHub Releases](https://github.com/KodyMike/rndSequencer/releases)
2. Download the latest `plugin_package.zip` from the release
3. Open Caido and navigate to Plugins
4. Click "Install Package" and select the downloaded zip file

### From Source
```bash
git clone https://github.com/KodyMike/rndSequencer.git
cd rndSequencer
pnpm install
pnpm build
```

The plugin package will be at `dist/plugin_package.zip`.

**Note:** This project uses `pnpm` (not npm) as the package manager.

## Usage

### Basic Workflow
1. Open Random Sequencer in Caido
2. Paste an HTTP request that returns tokens
3. Leave parameter name empty and click "Show Fields" to see the response
4. Copy the parameter name or use quick select buttons
5. Set sample count (recommended: 1000+ for reliable analysis)
6. Click "Start Collection" to begin analysis
7. Review security rating and detailed statistics

### Understanding Results

**Summary Metrics:**
- Total Samples: Number of tokens collected
- Unique Values: Count of distinct tokens
- Duplicates: Percentage of repeated tokens (high = security issue)
- Entropy: Shannon entropy character randomness score (higher = better)

**NIST 800-90B Entropy Analysis:**
- **Effective Security Bits**: Primary security metric (minimum: 128 bits for cryptographic use)
- **Shannon Entropy/bit**: Average uncertainty per bit (0-1 scale)
- **Min-Entropy/bit**: Worst-case guessability per bit (more conservative than Shannon)
- **Per-Position Min-Entropy**: Sum of min-entropy calculated at each character position
- **LZ Compression Ratio**: Detects compressible structure (< 1.05 is good)
- **Chi-Squared Test**: Bit uniformity (p-value ≥ 0.05 passes)
- **Serial Correlation**: Bit independence (|value| ≤ 0.1 is good)
- **Runs Test**: Randomness patterns (p-value ≥ 0.05 passes)
- **Collision Analysis**: Exact duplicates, near-duplicates, Hamming distance

**Security Ratings:**
- **Critical**: Effective security < 64 bits, serious issues detected
- **Warning**: Effective security 64-127 bits, some concerns found
- **Good**: Effective security ≥ 128 bits, minor improvements possible
- **Excellent**: Effective security ≥ 128 bits with all statistical tests passing

**Common Issues:**
- High duplicates: Tokens are reused across requests
- Sequential patterns: Tokens increment predictably
- Timestamp-based: Tokens based on current time
- Low min-entropy: One or more characters/positions are biased
- Failed statistical tests: Non-random bit distributions or patterns
- High LZ compression ratio: Tokens contain detectable structure

## Development

### Prerequisites

- Node.js 18+ or 20+
- pnpm package manager (required)

### Commands

```bash
pnpm install       # Install dependencies
pnpm build         # Build for production
```

## Analysis Methodology

### NIST 800-90B Entropy Analysis
This plugin implements entropy estimation based on NIST Special Publication 800-90B, which provides guidance for cryptographic random number generation.

**Shannon Entropy:**
```
H_shannon = -Σ p(x) * log₂(p(x))
```
Measures average uncertainty. However, Shannon entropy can be misleading when values are slightly biased.

**Min-Entropy (Primary Metric):**
```
H_min = -log₂(max(p(x)))
```
Measures worst-case guessability. This is the recommended metric for security assessment as it represents the attacker's best-case scenario.

**Per-Position Min-Entropy:**
For fixed-length tokens, calculates min-entropy at each character position independently, then sums them. This detects position-specific biases.

**Effective Security Bits:**
```
Effective bits = min(H_min, H_per_position, bit_length × H_min_per_bit)
```
The final security metric represents the actual cryptographic strength in bits.

### Statistical Tests

**Chi-Squared Test (Bit Uniformity):**
Tests if 0s and 1s are uniformly distributed in the bit representation. p-value ≥ 0.05 indicates uniform distribution.

**Serial Correlation (Independence):**
Measures correlation between consecutive bits. Values near 0 indicate independence. |correlation| > 0.1 suggests dependency.

**Runs Test (Randomness):**
Analyzes sequences of consecutive identical bits. p-value ≥ 0.05 indicates random patterns.

**LZ Compression Ratio:**
Uses LZ78-style compression to detect structure. Ratio > 1.05 indicates compressible (non-random) data.

### Security Thresholds
- **Effective Security Bits**: < 64 (Critical), 64-127 (Warning), ≥ 128 (Good/Excellent)
- **Duplicates**: > 10% (Critical), 5-10% (Warning), < 5% (Good)
- **Predictability Score**: > 50 (Critical), 20-50 (Warning), < 20 (Good)
- **Statistical Tests**: p-value < 0.05 or |correlation| > 0.1 indicates failure

### Pattern Detection
- Sequential: Detects incrementing numbers
- Timestamps: Identifies Unix timestamps (10-13 digits)
- Common prefix/suffix: Finds shared strings
- Bit entropy: Analyzes binary representation randomness

### Why Min-Entropy Over Shannon?
Shannon entropy measures average case, but attackers exploit worst-case scenarios. If one token value appears slightly more often, Shannon entropy stays high while min-entropy correctly drops, revealing the vulnerability. NIST 800-90B recommends min-entropy for security assessments.

## License

MIT License - see LICENSE file for details.

## Security Notice

This plugin is for defensive security testing only. Use only on applications you own or have explicit permission to test.

## Support

For issues or questions:
1. Check the Issues page for existing reports
2. Create a new issue with detailed information
3. Include plugin version and Caido version

## Acknowledgments

Built for the Caido security testing platform using the official plugin development framework.
