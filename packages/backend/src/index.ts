import type { DefineAPI, SDK } from "caido:plugin";
import { RequestSpec } from "caido:utils";

interface TokenCapture {
  token: string;
  requestSent: string;
  responseReceived: string;
  extractedFrom: string;
  responseHeaders?: Record<string, string | string[]>;
}

interface AnalysisResult {
  summary: {
    totalSamples: number;
    uniqueValues: number;
    duplicateCount: number;
    duplicatePercentage: number;
    entropy: number;
    averageLength: number;
    minLength: number;
    maxLength: number;
  };
  patterns: {
    sequential: boolean;
    sequentialCount: number;
    hasTimestamps: boolean;
    commonPrefix: string;
    commonSuffix: string;
    predictabilityScore: number;
  };
  characterAnalysis: {
    charset: string;
    alphabetic: number;
    numeric: number;
    special: number;
    hexadecimal: boolean;
    base64: boolean;
  };
  bitAnalysis: {
    totalBits: number;
    onesCount: number;
    zerosCount: number;
    bitEntropy: number;
  };
  entropyAnalysis: {
    shannonEntropyPerBit: number;
    minEntropyPerBit: number;
    perPositionMinEntropy: number;
    effectiveSecurityBits: number;
    chiSquaredPValue: number;
    serialCorrelation: number;
    runsTestPValue: number;
    lzCompressionRatio: number;
    estimatedEntropyRate: number;
    perPositionData?: Array<{
      position: number;
      entropy: number;
      mostCommonChar: string;
      frequency: number;
    }>;
  };
  collisionAnalysis: {
    exactDuplicates: number;
    nearDuplicates: number;
    averageHammingDistance: number;
  };
  security: {
    overallRating: 'CRITICAL' | 'WARNING' | 'GOOD' | 'EXCELLENT';
    issues: string[];
    warnings: string[];
    strengths: string[];
    effectiveBits: number;
    recommendedMinimum: number;
  };
}

let tokenCaptures: TokenCapture[] = [];

// Convert token to bit array
function tokenToBits(token: string, encoding: 'hex' | 'base64' | 'raw' = 'raw'): number[] {
  const bits: number[] = [];

  if (encoding === 'hex' && /^[0-9a-fA-F]+$/.test(token)) {
    for (let i = 0; i < token.length; i++) {
      const val = parseInt(token[i] || '0', 16);
      for (let j = 3; j >= 0; j--) {
        bits.push((val >> j) & 1);
      }
    }
  } else if (encoding === 'base64' && /^[A-Za-z0-9+/=]+$/.test(token)) {
    // Decode base64 to binary
    try {
      const decoded = atob(token.replace(/=/g, ''));
      for (let i = 0; i < decoded.length; i++) {
        const byte = decoded.charCodeAt(i);
        for (let j = 7; j >= 0; j--) {
          bits.push((byte >> j) & 1);
        }
      }
    } catch {
      // Fall back to raw
      return tokenToBits(token, 'raw');
    }
  } else {
    // Raw byte encoding
    for (let i = 0; i < token.length; i++) {
      const byte = token.charCodeAt(i);
      for (let j = 7; j >= 0; j--) {
        bits.push((byte >> j) & 1);
      }
    }
  }

  return bits;
}

// Shannon entropy calculation
function calculateEntropy(tokens: string[]): number {
  if (tokens.length === 0) return 0;

  const charFrequency = new Map<string, number>();
  let totalChars = 0;

  for (const token of tokens) {
    for (const char of token) {
      charFrequency.set(char, (charFrequency.get(char) || 0) + 1);
      totalChars++;
    }
  }

  let entropy = 0;
  for (const count of charFrequency.values()) {
    const probability = count / totalChars;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}

// Min-entropy: H_min = -log2(max(p_i))
function calculateMinEntropy(tokens: string[]): number {
  if (tokens.length === 0) return 0;

  const frequency = new Map<string, number>();
  for (const token of tokens) {
    frequency.set(token, (frequency.get(token) || 0) + 1);
  }

  const maxCount = Math.max(...frequency.values());
  const maxProb = maxCount / tokens.length;

  return -Math.log2(maxProb);
}

// Per-position min-entropy for fixed-length tokens
function calculatePerPositionMinEntropy(tokens: string[]): { totalEntropy: number, positionData: Array<{ position: number, entropy: number, mostCommonChar: string, frequency: number }> } {
  if (tokens.length === 0) return { totalEntropy: 0, positionData: [] };

  // Check if all tokens are same length
  const lengths = tokens.map(t => t.length);
  const allSameLength = lengths.every(l => l === lengths[0]);

  if (!allSameLength) {
    // Fall back to global min-entropy
    return { totalEntropy: calculateMinEntropy(tokens), positionData: [] };
  }

  const tokenLength = lengths[0] || 0;
  let totalMinEntropy = 0;
  const positionData: Array<{ position: number, entropy: number, mostCommonChar: string, frequency: number }> = [];

  // For each position
  for (let pos = 0; pos < tokenLength; pos++) {
    const charFreq = new Map<string, number>();

    for (const token of tokens) {
      const char = token[pos] || '';
      charFreq.set(char, (charFreq.get(char) || 0) + 1);
    }

    const maxCount = Math.max(...charFreq.values());
    const maxProb = maxCount / tokens.length;
    const posMinEntropy = -Math.log2(maxProb);

    // Find the most common character at this position
    let mostCommonChar = '';
    for (const [char, count] of charFreq.entries()) {
      if (count === maxCount) {
        mostCommonChar = char;
        break;
      }
    }

    positionData.push({
      position: pos,
      entropy: posMinEntropy,
      mostCommonChar,
      frequency: maxProb
    });

    totalMinEntropy += posMinEntropy;
  }

  return { totalEntropy: totalMinEntropy, positionData };
}

// Chi-squared test for uniformity
function chiSquaredTest(bits: number[]): number {
  if (bits.length < 100) return 1.0; // Not enough data

  const observed0 = bits.filter(b => b === 0).length;
  const observed1 = bits.filter(b => b === 1).length;
  const expected = bits.length / 2;

  const chiSq = Math.pow(observed0 - expected, 2) / expected +
                Math.pow(observed1 - expected, 2) / expected;

  // Degrees of freedom = 1 for binary
  // Approximate p-value for χ² distribution with df=1
  // Using complementary error function approximation
  const pValue = 1 - (1 - Math.exp(-chiSq / 2));

  return Math.max(0, Math.min(1, pValue));
}

// Serial correlation coefficient for bit sequence
function serialCorrelation(bits: number[]): number {
  if (bits.length < 2) return 0;

  let sum1 = 0, sum2 = 0, sum12 = 0;
  const n = bits.length - 1;

  for (let i = 0; i < n; i++) {
    sum1 += bits[i] || 0;
    sum2 += bits[i + 1] || 0;
    sum12 += (bits[i] || 0) * (bits[i + 1] || 0);
  }

  const mean1 = sum1 / n;
  const mean2 = sum2 / n;
  const covariance = (sum12 / n) - (mean1 * mean2);

  // Standard deviations
  let var1 = 0, var2 = 0;
  for (let i = 0; i < n; i++) {
    var1 += Math.pow((bits[i] || 0) - mean1, 2);
    var2 += Math.pow((bits[i + 1] || 0) - mean2, 2);
  }
  var1 /= n;
  var2 /= n;

  const stdDev = Math.sqrt(var1 * var2);

  return stdDev === 0 ? 0 : covariance / stdDev;
}

// Runs test for randomness
function runsTest(bits: number[]): number {
  if (bits.length < 20) return 1.0;

  // Count runs
  let runs = 1;
  for (let i = 1; i < bits.length; i++) {
    if (bits[i] !== bits[i - 1]) runs++;
  }

  const n0 = bits.filter(b => b === 0).length;
  const n1 = bits.filter(b => b === 1).length;
  const n = bits.length;

  // Expected runs and variance under null hypothesis
  const expectedRuns = (2 * n0 * n1) / n + 1;
  const variance = (2 * n0 * n1 * (2 * n0 * n1 - n)) / (n * n * (n - 1));

  if (variance === 0) return 1.0;

  const z = (runs - expectedRuns) / Math.sqrt(variance);

  // Approximate p-value (two-tailed)
  const pValue = 2 * (1 - normalCDF(Math.abs(z)));

  return Math.max(0, Math.min(1, pValue));
}

// Standard normal CDF approximation
function normalCDF(z: number): number {
  const t = 1 / (1 + 0.2316419 * Math.abs(z));
  const d = 0.3989423 * Math.exp(-z * z / 2);
  const prob = d * t * (0.3193815 + t * (-0.3565638 + t * (1.781478 + t * (-1.821256 + t * 1.330274))));
  return z > 0 ? 1 - prob : prob;
}

// LZ compression-based entropy estimate
function lzEntropyEstimate(bits: number[]): number {
  if (bits.length < 100) return 0;

  // Simple LZ78-style compression
  const dictionary = new Map<string, number>();
  let dictionarySize = 1;
  let currentString = '';
  let compressedLength = 0;

  for (const bit of bits) {
    const newString = currentString + bit;

    if (dictionary.has(newString)) {
      currentString = newString;
    } else {
      dictionary.set(newString, dictionarySize++);
      compressedLength += Math.ceil(Math.log2(dictionarySize));
      currentString = String(bit);
    }
  }

  // Entropy rate = compressed bits / original bits
  return compressedLength / bits.length;
}

// Hamming distance between two strings
function hammingDistance(s1: string, s2: string): number {
  if (s1.length !== s2.length) return Math.max(s1.length, s2.length);

  let distance = 0;
  for (let i = 0; i < s1.length; i++) {
    if (s1[i] !== s2[i]) distance++;
  }
  return distance;
}

// Collision and near-duplicate analysis
function analyzeCollisions(tokens: string[]): { exactDuplicates: number; nearDuplicates: number; averageHammingDistance: number } {
  if (tokens.length < 2) {
    return { exactDuplicates: 0, nearDuplicates: 0, averageHammingDistance: 0 };
  }

  const seen = new Set<string>();
  let exactDuplicates = 0;
  let nearDuplicates = 0;
  let totalDistance = 0;
  let comparisons = 0;

  // Check exact duplicates
  for (const token of tokens) {
    if (seen.has(token)) {
      exactDuplicates++;
    }
    seen.add(token);
  }

  // Check near-duplicates (Hamming distance ≤ 2) and average distance
  // Sample to avoid O(n²) on large sets
  const sampleSize = Math.min(1000, tokens.length);
  const step = Math.floor(tokens.length / sampleSize);

  for (let i = 0; i < tokens.length; i += step) {
    for (let j = i + step; j < tokens.length; j += step) {
      const dist = hammingDistance(tokens[i] || '', tokens[j] || '');
      totalDistance += dist;
      comparisons++;

      if (dist > 0 && dist <= 2) {
        nearDuplicates++;
      }
    }
  }

  const averageHammingDistance = comparisons > 0 ? totalDistance / comparisons : 0;

  return { exactDuplicates, nearDuplicates, averageHammingDistance };
}

// Bit-level entropy calculation
function calculateBitEntropy(tokens: string[]): { totalBits: number; onesCount: number; zerosCount: number; bitEntropy: number } {
  let onesCount = 0;
  let zerosCount = 0;

  for (const token of tokens) {
    for (const char of token) {
      const charCode = char.charCodeAt(0);
      for (let i = 0; i < 8; i++) {
        if ((charCode >> i) & 1) {
          onesCount++;
        } else {
          zerosCount++;
        }
      }
    }
  }

  const totalBits = onesCount + zerosCount;
  if (totalBits === 0) return { totalBits: 0, onesCount: 0, zerosCount: 0, bitEntropy: 0 };

  const pOne = onesCount / totalBits;
  const pZero = zerosCount / totalBits;
  const bitEntropy = -(pOne * Math.log2(pOne || 1) + pZero * Math.log2(pZero || 1));

  return { totalBits, onesCount, zerosCount, bitEntropy };
}

// Detect sequential patterns
function detectSequentialPatterns(tokens: string[]): { isSequential: boolean; count: number } {
  let sequentialCount = 0;

  for (let i = 1; i < tokens.length; i++) {
    const prev = tokens[i - 1];
    const curr = tokens[i];

    // Check if numeric and sequential
    const prevNum = parseInt(prev || '');
    const currNum = parseInt(curr || '');

    if (!isNaN(prevNum) && !isNaN(currNum) && currNum === prevNum + 1) {
      sequentialCount++;
    }
  }

  const isSequential = sequentialCount > tokens.length * 0.5;
  return { isSequential, count: sequentialCount };
}

// Detect timestamps
function detectTimestamps(tokens: string[]): boolean {
  let timestampCount = 0;

  for (const token of tokens) {
    // Unix timestamp (10 or 13 digits)
    if (/^\d{10,13}$/.test(token)) {
      const num = parseInt(token);
      // Check if it's a reasonable timestamp (between 2000 and 2100)
      if (num > 946684800 && num < 4102444800) {
        timestampCount++;
      }
    }
  }

  return timestampCount > tokens.length * 0.3;
}

// Find common prefix/suffix
function findCommonPrefixSuffix(tokens: string[]): { prefix: string; suffix: string } {
  if (tokens.length === 0) return { prefix: '', suffix: '' };

  // Find common prefix
  let prefix = tokens[0] || '';
  for (const token of tokens) {
    let i = 0;
    while (i < prefix.length && i < token.length && prefix[i] === token[i]) {
      i++;
    }
    prefix = prefix.substring(0, i);
  }

  // Find common suffix
  let suffix = tokens[0] || '';
  for (const token of tokens) {
    let i = 0;
    while (i < suffix.length && i < token.length &&
           suffix[suffix.length - 1 - i] === token[token.length - 1 - i]) {
      i++;
    }
    suffix = suffix.substring(suffix.length - i);
  }

  return { prefix, suffix };
}

// Character analysis
function analyzeCharacters(tokens: string[]): { charset: string; alphabetic: number; numeric: number; special: number; hexadecimal: boolean; base64: boolean } {
  const charSet = new Set<string>();
  let alphabetic = 0;
  let numeric = 0;
  let special = 0;

  for (const token of tokens) {
    for (const char of token) {
      charSet.add(char);
      if (/[a-zA-Z]/.test(char)) alphabetic++;
      else if (/[0-9]/.test(char)) numeric++;
      else special++;
    }
  }

  const charset = Array.from(charSet).sort().join('');
  const hexadecimal = /^[0-9a-fA-F]+$/.test(charset);
  const base64 = /^[A-Za-z0-9+/=]+$/.test(charset);

  return { charset, alphabetic, numeric, special, hexadecimal, base64 };
}

// Comprehensive analysis
function analyzeTokens(captures: TokenCapture[]): AnalysisResult {
  const tokens = captures.map(c => c.token).filter(t => t && t !== 'Not found' && !t.startsWith('Request failed') && !t.startsWith('Parse Error'));
  const failedCaptures = captures.filter(c => c.token.startsWith('Request failed') || c.token.startsWith('Parse Error'));
  const notFoundCaptures = captures.filter(c => c.token === 'Not found');

  if (tokens.length === 0) {
    // Check if we have captures but no valid tokens
    let errorMessage = 'No valid tokens could be extracted from responses.';
    let errorType = 'ERROR';

    if (notFoundCaptures.length === captures.length) {
      errorMessage = `Parameter not found in any of the ${captures.length} responses. Please verify the parameter name is correct.`;
      errorType = 'PARAMETER_NOT_FOUND';
    } else if (failedCaptures.length > 0) {
      errorMessage = `All ${failedCaptures.length} requests failed. Check network connectivity, CORS settings, or request configuration. Common issues: incorrect host/port, SSL errors, or server not responding.`;
      errorType = 'REQUEST_FAILED';
    }

    return {
      summary: { totalSamples: captures.length, uniqueValues: 0, duplicateCount: 0, duplicatePercentage: 0, entropy: 0, averageLength: 0, minLength: 0, maxLength: 0 },
      patterns: { sequential: false, sequentialCount: 0, hasTimestamps: false, commonPrefix: '', commonSuffix: '', predictabilityScore: 0 },
      characterAnalysis: { charset: '', alphabetic: 0, numeric: 0, special: 0, hexadecimal: false, base64: false },
      bitAnalysis: { totalBits: 0, onesCount: 0, zerosCount: 0, bitEntropy: 0 },
      entropyAnalysis: { shannonEntropyPerBit: 0, minEntropyPerBit: 0, perPositionMinEntropy: 0, effectiveSecurityBits: 0, chiSquaredPValue: 0, serialCorrelation: 0, runsTestPValue: 0, lzCompressionRatio: 0, estimatedEntropyRate: 0, perPositionData: [] },
      collisionAnalysis: { exactDuplicates: 0, nearDuplicates: 0, averageHammingDistance: 0 },
      security: { overallRating: 'CRITICAL', issues: [`${errorType}:${errorMessage}`], warnings: [], strengths: [], effectiveBits: 0, recommendedMinimum: 128 }
    };
  }

  // Check if we have partial failures - warn the user
  const partialFailures: string[] = [];
  if (failedCaptures.length > 0) {
    const successRate = ((tokens.length / captures.length) * 100).toFixed(1);
    partialFailures.push(`${failedCaptures.length} of ${captures.length} requests failed (${successRate}% success rate). Results may not be statistically reliable.`);
  }

  // Summary
  const uniqueTokens = new Set(tokens);
  const uniqueValues = uniqueTokens.size;
  const duplicateCount = tokens.length - uniqueValues;
  const duplicatePercentage = (duplicateCount / tokens.length) * 100;
  const entropy = calculateEntropy(tokens);
  const lengths = tokens.map(t => t.length);
  const averageLength = lengths.reduce((a, b) => a + b, 0) / lengths.length;
  const minLength = Math.min(...lengths);
  const maxLength = Math.max(...lengths);

  // Patterns
  const sequential = detectSequentialPatterns(tokens);
  const hasTimestamps = detectTimestamps(tokens);
  const { prefix, suffix } = findCommonPrefixSuffix(tokens);

  // Predictability score (0-100, higher = more predictable)
  let predictabilityScore = 0;
  if (sequential.isSequential) predictabilityScore += 40;
  if (hasTimestamps) predictabilityScore += 30;
  if (duplicatePercentage > 10) predictabilityScore += 20;
  if (prefix.length > 3) predictabilityScore += 10;

  // Character analysis
  const charAnalysis = analyzeCharacters(tokens);

  // Bit analysis
  const bitAnalysis = calculateBitEntropy(tokens);

  // === NEW: Comprehensive NIST 800-90B-style Entropy Analysis ===

  // Detect encoding type
  const isHex = charAnalysis.hexadecimal;
  const isBase64 = charAnalysis.base64;
  const encoding: 'hex' | 'base64' | 'raw' = isHex ? 'hex' : (isBase64 ? 'base64' : 'raw');

  // Convert all tokens to bits
  const allBits: number[] = [];
  for (const token of tokens) {
    allBits.push(...tokenToBits(token, encoding));
  }

  const totalBits = allBits.length;

  // Shannon entropy per bit
  const bit0Count = allBits.filter(b => b === 0).length;
  const bit1Count = allBits.filter(b => b === 1).length;
  const p0 = bit0Count / totalBits;
  const p1 = bit1Count / totalBits;
  const shannonEntropyPerBit = p0 > 0 && p1 > 0 ? -(p0 * Math.log2(p0) + p1 * Math.log2(p1)) : 0;

  // Min-entropy (global)
  const minEntropy = calculateMinEntropy(tokens);
  const avgBitsPerToken = totalBits / tokens.length;
  const minEntropyPerBit = minEntropy / avgBitsPerToken;

  // Per-position min-entropy
  const perPositionResult = calculatePerPositionMinEntropy(tokens);
  const perPositionMinEntropy = perPositionResult.totalEntropy;
  const perPositionMinEntropyPerBit = perPositionMinEntropy / avgBitsPerToken;

  // Effective security bits (worst case - use the minimum of all estimators)
  const effectiveSecurityBits = Math.min(
    minEntropy,
    perPositionMinEntropy,
    avgBitsPerToken * minEntropyPerBit
  );

  // Chi-squared test for uniformity
  const chiSquaredPValue = chiSquaredTest(allBits);

  // Serial correlation
  const serialCorr = serialCorrelation(allBits);

  // Runs test
  const runsTestPValue = runsTest(allBits);

  // LZ compression-based entropy estimate
  const lzEntropy = lzEntropyEstimate(allBits);
  const lzCompressionRatio = lzEntropy / shannonEntropyPerBit;
  const estimatedEntropyRate = lzEntropy;

  // Collision analysis
  const collisionAnalysis = analyzeCollisions(tokens);

  // Security assessment
  const issues: string[] = [];
  const warnings: string[] = [];
  const strengths: string[] = [];

  // === NEW: NIST-style Security Assessment based on Min-Entropy ===

  const recommendedMinimum = 128; // NIST recommendation for session tokens

  // Effective bits assessment (most critical)
  if (effectiveSecurityBits < 64) {
    issues.push(`CRITICAL: Effective security is only ${effectiveSecurityBits.toFixed(1)} bits (minimum 128 bits recommended). Tokens are easily guessable.`);
  } else if (effectiveSecurityBits < 80) {
    issues.push(`Effective security is ${effectiveSecurityBits.toFixed(1)} bits. Vulnerable to brute-force attacks (128+ bits recommended).`);
  } else if (effectiveSecurityBits < 128) {
    warnings.push(`Effective security is ${effectiveSecurityBits.toFixed(1)} bits. Below recommended 128 bits for session tokens.`);
  } else {
    strengths.push(`Strong effective security: ${effectiveSecurityBits.toFixed(1)} bits (exceeds 128-bit minimum).`);
  }

  // Min-entropy checks
  if (minEntropyPerBit < 0.5) {
    issues.push(`Very low min-entropy per bit (${minEntropyPerBit.toFixed(3)}). Tokens have predictable patterns.`);
  } else if (minEntropyPerBit < 0.8) {
    warnings.push(`Low min-entropy per bit (${minEntropyPerBit.toFixed(3)}). Some predictability present.`);
  } else if (minEntropyPerBit > 0.95) {
    strengths.push(`Excellent min-entropy per bit (${minEntropyPerBit.toFixed(3)}).`);
  }

  // Shannon entropy (kept for reference, but not primary)
  if (entropy < 3.0) warnings.push(`Low Shannon entropy (${entropy.toFixed(2)}). May indicate limited character set.`);
  else if (entropy >= 4.5) strengths.push(`Good Shannon entropy (${entropy.toFixed(2)}).`);

  // Chi-squared uniformity test
  if (chiSquaredPValue < 0.01) {
    issues.push(`Chi-squared test failed (p=${chiSquaredPValue.toFixed(4)}). Bit distribution is non-uniform.`);
  } else if (chiSquaredPValue < 0.05) {
    warnings.push(`Chi-squared test marginal (p=${chiSquaredPValue.toFixed(4)}). Slight non-uniformity detected.`);
  } else {
    strengths.push(`Chi-squared test passed (p=${chiSquaredPValue.toFixed(4)}). Uniform bit distribution.`);
  }

  // Serial correlation test
  const absCorr = Math.abs(serialCorr);
  if (absCorr > 0.3) {
    issues.push(`High serial correlation (${serialCorr.toFixed(3)}). Consecutive bits are dependent.`);
  } else if (absCorr > 0.1) {
    warnings.push(`Moderate serial correlation (${serialCorr.toFixed(3)}). Some bit dependencies present.`);
  } else {
    strengths.push(`Low serial correlation (${serialCorr.toFixed(3)}). Bits are independent.`);
  }

  // Runs test
  if (runsTestPValue < 0.01) {
    issues.push(`Runs test failed (p=${runsTestPValue.toFixed(4)}). Non-random run patterns detected.`);
  } else if (runsTestPValue < 0.05) {
    warnings.push(`Runs test marginal (p=${runsTestPValue.toFixed(4)}). Possible run pattern issues.`);
  } else {
    strengths.push(`Runs test passed (p=${runsTestPValue.toFixed(4)}). Random run distribution.`);
  }

  // LZ compression entropy
  if (lzCompressionRatio > 1.2) {
    issues.push(`High LZ compression ratio (${lzCompressionRatio.toFixed(2)}). Structure detected in data.`);
  } else if (lzCompressionRatio > 1.05) {
    warnings.push(`Elevated LZ compression ratio (${lzCompressionRatio.toFixed(2)}). Some structure present.`);
  } else {
    strengths.push(`Good LZ compression ratio (${lzCompressionRatio.toFixed(2)}). Minimal structure.`);
  }

  // Collision analysis
  if (collisionAnalysis.nearDuplicates > tokens.length * 0.01) {
    warnings.push(`${collisionAnalysis.nearDuplicates} near-duplicate tokens found (Hamming distance ≤ 2).`);
  } else if (collisionAnalysis.nearDuplicates === 0) {
    strengths.push(`No near-duplicate tokens (Hamming distance > 2).`);
  }

  // Duplicate checks
  if (duplicatePercentage > 10) issues.push(`${duplicatePercentage.toFixed(1)}% exact duplicate tokens. Poor randomness.`);
  else if (duplicatePercentage > 5) warnings.push(`${duplicatePercentage.toFixed(1)}% exact duplicate tokens.`);
  else if (duplicatePercentage < 2) strengths.push(`Very few exact duplicates (${duplicatePercentage.toFixed(1)}%).`);

  // Sequential checks
  if (sequential.isSequential) issues.push('Sequential pattern detected. Tokens are predictable.');
  else strengths.push('No sequential patterns detected.');

  // Timestamp checks
  if (hasTimestamps) issues.push('Timestamp-based tokens detected. Highly predictable.');

  // Predictability checks
  if (predictabilityScore > 50) issues.push(`High predictability score (${predictabilityScore}/100).`);
  else if (predictabilityScore > 20) warnings.push(`Moderate predictability score (${predictabilityScore}/100).`);
  else strengths.push(`Low predictability score (${predictabilityScore}/100).`);

  // Add partial failure warnings
  warnings.push(...partialFailures);

  // Overall rating
  let overallRating: 'CRITICAL' | 'WARNING' | 'GOOD' | 'EXCELLENT';
  if (issues.length > 0) overallRating = 'CRITICAL';
  else if (warnings.length > 0) overallRating = 'WARNING';
  else if (strengths.length >= 3) overallRating = 'EXCELLENT';
  else overallRating = 'GOOD';

  return {
    summary: {
      totalSamples: tokens.length,
      uniqueValues,
      duplicateCount,
      duplicatePercentage,
      entropy,
      averageLength,
      minLength,
      maxLength
    },
    patterns: {
      sequential: sequential.isSequential,
      sequentialCount: sequential.count,
      hasTimestamps,
      commonPrefix: prefix,
      commonSuffix: suffix,
      predictabilityScore
    },
    characterAnalysis: charAnalysis,
    bitAnalysis,
    entropyAnalysis: {
      shannonEntropyPerBit,
      minEntropyPerBit,
      perPositionMinEntropy: perPositionMinEntropyPerBit,
      effectiveSecurityBits,
      chiSquaredPValue,
      serialCorrelation: serialCorr,
      runsTestPValue,
      lzCompressionRatio,
      estimatedEntropyRate,
      perPositionData: perPositionResult.positionData
    },
    collisionAnalysis,
    security: {
      overallRating,
      issues,
      warnings,
      strengths,
      effectiveBits: effectiveSecurityBits,
      recommendedMinimum
    }
  };
}

function extractTokenFromResponse(responseBody: string, headers: any, parameterName: string): { token: string | null, extractedFrom: string } {
  // First check response headers for cookies
  if (headers) {
    const setCookieHeaders = headers['set-cookie'] || headers['Set-Cookie'];
    if (setCookieHeaders) {
      const cookieArray = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
      for (const cookieHeader of cookieArray) {
        const cookieRegex = new RegExp(`${parameterName}=([^;\\s]+)`, 'i');
        const cookieMatch = cookieHeader.match(cookieRegex);
        if (cookieMatch) {
          return { token: decodeURIComponent(cookieMatch[1]), extractedFrom: 'Set-Cookie header' };
        }
      }
    }
    
    // Check other headers
    for (const [headerName, headerValue] of Object.entries(headers)) {
      if (typeof headerValue === 'string' && headerName.toLowerCase().includes(parameterName.toLowerCase())) {
        return { token: headerValue, extractedFrom: `${headerName} header` };
      }
    }
  }

  try {
    // Try JSON first
    const jsonData = JSON.parse(responseBody);
    if (jsonData[parameterName]) {
      return { token: String(jsonData[parameterName]), extractedFrom: 'JSON response' };
    }
    
    // Try nested JSON paths
    for (const key in jsonData) {
      if (typeof jsonData[key] === 'object' && jsonData[key] && jsonData[key][parameterName]) {
        return { token: String(jsonData[key][parameterName]), extractedFrom: `JSON response (${key}.${parameterName})` };
      }
    }
  } catch {
    // Not JSON, try other formats
  }
  
  // Try URL-encoded format: param=value
  const urlEncodedRegex = new RegExp(`${parameterName}=([^&\\n\\r]+)`, 'i');
  const urlMatch = responseBody.match(urlEncodedRegex);
  if (urlMatch && urlMatch[1]) {
    return { token: decodeURIComponent(urlMatch[1]), extractedFrom: 'URL-encoded response' };
  }
  
  // Try HTML input field: <input name="param" value="token">
  const inputRegex = new RegExp(`<input[^>]*name=["']${parameterName}["'][^>]*value=["']([^"']+)["']`, 'i');
  const inputMatch = responseBody.match(inputRegex);
  if (inputMatch && inputMatch[1]) {
    return { token: inputMatch[1], extractedFrom: 'HTML input field' };
  }
  
  // Try meta tag: <meta name="param" content="token">
  const metaRegex = new RegExp(`<meta[^>]*name=["']${parameterName}["'][^>]*content=["']([^"']+)["']`, 'i');
  const metaMatch = responseBody.match(metaRegex);
  if (metaMatch && metaMatch[1]) {
    return { token: metaMatch[1], extractedFrom: 'HTML meta tag' };
  }
  
  // Try data attributes: data-param="token"
  const dataAttrRegex = new RegExp(`data-${parameterName}=["']([^"']+)["']`, 'i');
  const dataMatch = responseBody.match(dataAttrRegex);
  if (dataMatch && dataMatch[1]) {
    return { token: dataMatch[1], extractedFrom: 'HTML data attribute' };
  }
  
  // Try JavaScript variable assignment: var param = "token"
  const jsVarRegex = new RegExp(`(?:var|let|const)\\s+${parameterName}\\s*=\\s*["']([^"']+)["']`, 'i');
  const jsMatch = responseBody.match(jsVarRegex);
  if (jsMatch && jsMatch[1]) {
    return { token: jsMatch[1], extractedFrom: 'JavaScript variable' };
  }
  
  return { token: null, extractedFrom: 'Not found' };
}

interface RateLimitConfig {
  enabled: boolean;
  requestsPerBatch: number;
  delayBetweenBatches: number;
  retryOn429: boolean;
  maxRetries: number;
  retryDelay: number;
  backoffMultiplier: number;
}

interface CollectionConfig {
  httpRequest: string;
  parameterName: string;
  count: number;
  rateLimit?: RateLimitConfig;
}

export type API = DefineAPI<{
  test: () => string;
  startCollection: (config: CollectionConfig) => Promise<TokenCapture[]>;
  getTokens: () => TokenCapture[];
  analyzeTokens: () => AnalysisResult;
  exportCSV: () => string;
  exportJSON: () => string;
}>;

export function init(sdk: SDK<API>) {
  sdk.api.register("test", () => {
    return "Hello from backend";
  });
  
  sdk.api.register("startCollection", async (sdkInstance, config: CollectionConfig) => {
    tokenCaptures = [];
    
    try {
      // Parse the HTTP request
      const lines = config.httpRequest.split('\n');
      const requestLine = lines[0];
      if (!requestLine) {
        throw new Error('Invalid HTTP request: missing request line');
      }
      const requestParts = requestLine.split(' ');
      const method = requestParts[0] || 'GET';
      const path = requestParts[1] || '/';
      
      // Find Host header
      let host = 'localhost';
      let headers: Record<string, string> = {};
      let bodyStart = -1;
      
      for (let i = 1; i < lines.length; i++) {
        const line = lines[i]?.trim() || '';
        if (line === '') {
          bodyStart = i + 1;
          break;
        }
        
        const colonIndex = line.indexOf(':');
        if (colonIndex > -1) {
          const headerName = line.substring(0, colonIndex).trim();
          const headerValue = line.substring(colonIndex + 1).trim();
          headers[headerName.toLowerCase()] = headerValue;
          
          if (headerName.toLowerCase() === 'host') {
            host = headerValue;
          }
        }
      }
      
      // Get body if exists
      let body = '';
      if (bodyStart > -1 && bodyStart < lines.length) {
        body = lines.slice(bodyStart).join('\n');
      }
      
      // Build request string for display
      const requestStr = `${method} ${path} HTTP/1.1\nHost: ${host}\n${Object.entries(headers).filter(([k]) => k !== 'host').map(([k,v]) => `${k}: ${v}`).join('\n')}\n\n${body}`;
      
      // Determine protocol - default to http if not specified
      let protocol = 'http';
      let hostOnly = host;
      let port = 80;
      
      // Check if host includes port
      if (host.includes(':')) {
        const parts = host.split(':');
        hostOnly = parts[0] || host;
        port = parseInt(parts[1] || '80') || 80;
        // If port 443, assume https
        if (port === 443) {
          protocol = 'https';
        }
      }
      
      // Override protocol if path starts with https
      if (path.toLowerCase().startsWith('/https') || path.toLowerCase().includes('https')) {
        protocol = 'https';
        port = port === 80 ? 443 : port;
      }
      
      // Note: We allow all hosts including localhost variants
      // The user is responsible for ensuring the host is reachable
      
      // Helper function to send a single request with retry logic
      const sendRequestWithRetry = async (requestNum: number): Promise<TokenCapture> => {
        const baseUrl = `${protocol}://${hostOnly}${port !== (protocol === 'https' ? 443 : 80) ? ':' + port : ''}`;
        const fullUrl = baseUrl + path;

        let lastError: any = null;
        const maxAttempts = config.rateLimit?.enabled && config.rateLimit.retryOn429 ? config.rateLimit.maxRetries + 1 : 1;

        for (let attempt = 0; attempt < maxAttempts; attempt++) {
          try {
            // Create RequestSpec
            const spec = new RequestSpec(fullUrl);
            spec.setMethod(method || 'GET');

            // Set headers
            const filteredHeaders = Object.entries(headers).filter(([name]) =>
              name.toLowerCase() !== 'host' &&
              name.toLowerCase() !== 'content-length'
            );

            for (const [name, value] of filteredHeaders) {
              try {
                spec.setHeader(name, value);
              } catch (headerError) {
                // Skip problematic headers
              }
            }

            // Set body if needed
            if (body.trim() && ['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) {
              spec.setBody(body);
            }

            // Send request
            const response = await sdkInstance.requests.send(spec);
            const statusCode = response.response.getCode();

            // Check for rate limit response
            if (statusCode === 429 && config.rateLimit?.enabled && config.rateLimit.retryOn429 && attempt < maxAttempts - 1) {
              const retryAfterHeader = response.response.getHeader('Retry-After');
              let waitTime = config.rateLimit.retryDelay * Math.pow(config.rateLimit.backoffMultiplier, attempt);

              // If server provided Retry-After header, use it
              if (retryAfterHeader) {
                const retryAfterSeconds = parseInt(String(retryAfterHeader));
                if (!isNaN(retryAfterSeconds)) {
                  waitTime = retryAfterSeconds * 1000;
                }
              }

              await new Promise(resolve => setTimeout(resolve, waitTime));
              continue; // Retry
            }

            // Get response data
            const responseBody = response.response.getBody()?.toString() || '';
            const responseHeaders = response.response.getHeaders() || {};

            // Extract token
            const result = extractTokenFromResponse(responseBody, responseHeaders, config.parameterName);

            return {
              token: result.token || 'Not found',
              requestSent: requestStr,
              responseReceived: responseBody.substring(0, 2000) + (responseBody.length > 2000 ? '...' : ''),
              extractedFrom: result.extractedFrom,
              responseHeaders: responseHeaders
            };
          } catch (error) {
            lastError = error;

            // Retry on error if configured
            if (config.rateLimit?.enabled && config.rateLimit.retryOn429 && attempt < maxAttempts - 1) {
              const waitTime = config.rateLimit.retryDelay * Math.pow(config.rateLimit.backoffMultiplier, attempt);
              await new Promise(resolve => setTimeout(resolve, waitTime));
              continue;
            }
          }
        }

        // All retries failed
        const errorMessage = lastError instanceof Error ? lastError.message : String(lastError);
        return {
          token: `Request failed`,
          requestSent: requestStr,
          responseReceived: `Error: ${errorMessage}\nAttempted URL: ${baseUrl + path}\nMethod: ${method || 'GET'}\nRequest #${requestNum}`,
          extractedFrom: `Error: ${errorMessage}`
        };
      };

      // Collect tokens by sending real requests
      const rateLimit = config.rateLimit;

      for (let i = 0; i < config.count; i++) {
        // Send request
        const capture = await sendRequestWithRetry(i + 1);
        tokenCaptures.push(capture);

        // Apply rate limiting if enabled
        if (rateLimit?.enabled) {
          // Check if we need a batch delay
          const isLastInBatch = (i + 1) % rateLimit.requestsPerBatch === 0;
          const isNotLastRequest = i < config.count - 1;

          if (isLastInBatch && isNotLastRequest) {
            // Delay between batches
            await new Promise(resolve => setTimeout(resolve, rateLimit.delayBetweenBatches));
          } else if (isNotLastRequest) {
            // Small delay between requests in same batch (100ms default)
            await new Promise(resolve => setTimeout(resolve, 100));
          }
        } else {
          // Default small delay when rate limiting is disabled
          if (i < config.count - 1) {
            await new Promise(resolve => setTimeout(resolve, 100));
          }
        }
      }
    } catch (error) {
      // If parsing fails, add error
      const capture: TokenCapture = {
        token: `Parse Error: ${error}`,
        requestSent: config.httpRequest,
        responseReceived: `Failed to parse request: ${error}`,
        extractedFrom: 'Parse Error'
      };
      tokenCaptures.push(capture);
    }
    
    return tokenCaptures;
  });
  
  sdk.api.register("getTokens", () => {
    return tokenCaptures;
  });

  sdk.api.register("analyzeTokens", () => {
    return analyzeTokens(tokenCaptures);
  });

  sdk.api.register("exportCSV", () => {
    if (tokenCaptures.length === 0) return '';

    const headers = ['Index', 'Token', 'Length', 'Extracted From', 'Request Sent', 'Response Received'];

    const escapeCSV = (value: string) => {
      // Escape quotes and wrap in quotes if contains special chars
      const escaped = value.replace(/"/g, '""');
      return `"${escaped}"`;
    };

    const rows = tokenCaptures.map((capture, index) => [
      index + 1,
      capture.token,
      capture.token.length,
      capture.extractedFrom,
      capture.requestSent,
      capture.responseReceived
    ]);

    const csv = [
      headers.map(h => escapeCSV(h)).join(','),
      ...rows.map(row => row.map(cell => escapeCSV(String(cell))).join(','))
    ].join('\n');

    return csv;
  });

  sdk.api.register("exportJSON", () => {
    const analysis = analyzeTokens(tokenCaptures);
    return JSON.stringify({
      timestamp: new Date().toISOString(),
      tokenCaptures,
      analysis
    }, null, 2);
  });
}