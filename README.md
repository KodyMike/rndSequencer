# Caido Random Sequencer

A plugin for Caido that analyzes token randomness and predictability. This plugin helps security researchers assess the cryptographic strength of session tokens, CSRF tokens, and other security-critical parameters.

## Features

### Token Analysis
- Multi-source extraction from URLs, form data, JSON, cookies, and HTTP headers
- Statistical analysis with entropy calculation and duplicate detection
- Pattern detection for sequential numbers, timestamps, and common prefixes/suffixes
- Predictability scoring based on multiple factors

### Security Assessment
- Automated security rating (Critical, Warning, Good, Excellent)
- Character-level and bit-level entropy analysis
- Duplicate percentage tracking
- Security recommendations based on findings

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
- Entropy: Character randomness score (higher = better)

**Security Ratings:**
- Critical: Serious issues detected, tokens are predictable or reused
- Warning: Some concerns found, review recommended
- Good: No major issues but could be improved
- Excellent: Strong randomness with multiple positive indicators

**Common Issues:**
- High duplicates: Tokens are reused across requests
- Sequential patterns: Tokens increment predictably
- Timestamp-based: Tokens based on current time
- Low entropy: Limited character variety

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

### Entropy Calculation
Shannon entropy formula:
```
H(X) = -Σ p(x) * log₂(p(x))
```
Where p(x) is the probability of character x.

### Security Thresholds
- Entropy: < 3.0 (Critical), 3.0-4.0 (Low), 4.0-4.5 (Moderate), > 4.5 (High)
- Duplicates: > 10% (Critical), 5-10% (Warning), < 5% (Good)
- Predictability Score: > 50 (Critical), 20-50 (Warning), < 20 (Good)

### Pattern Detection
- Sequential: Detects incrementing numbers
- Timestamps: Identifies Unix timestamps (10-13 digits)
- Common prefix/suffix: Finds shared strings
- Bit entropy: Analyzes binary representation randomness

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
