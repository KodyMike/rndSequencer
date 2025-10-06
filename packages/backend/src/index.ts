import type { DefineAPI, SDK } from "caido:plugin";
import { RequestSpec } from "caido:utils";
// Declare atob for TS in non-DOM environments; provided by Caido at runtime
declare function atob(data: string): string;

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
      coverage?: number;
    }>;
    perPositionRawData?: Array<{
      position: number;
      entropy: number;
      normalizedEntropy: number;
      mostCommonChar: string;
      frequency: number;
      coverage: number;
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
  statisticalTests?: {
    basis: 'raw_string' | 'decoded_bytes';
    alpha: number;
    tests: Array<{
      name: string;
      applicableCount: number;
      passCount: number;
      passRate: number;
      medianP: number;
      notes?: string;
      pValues?: (number | null)[];
    }>;
  };
}

let tokenCaptures: TokenCapture[] = [];
let activeRunId: string | null = null;
const cancelledRuns = new Set<string>();

// ---- Robust decoding to bytes ----
function hasTextEncoder(): boolean {
  try {
    // @ts-ignore
    return typeof TextEncoder !== 'undefined';
  } catch {
    return false;
  }
}

function stringToUtf8Bytes(s: string): number[] {
  try {
    // @ts-ignore
    if (hasTextEncoder()) return Array.from(new TextEncoder().encode(s));
  } catch {}
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) out.push(s.charCodeAt(i) & 0xff);
  return out;
}

function tryDecodeHex(token: string): number[] | null {
  const clean = token.replace(/\s+/g, '');
  if (!/^[0-9a-fA-F]+$/.test(clean)) return null;
  if (clean.length % 2 !== 0) return null;
  const bytes: number[] = [];
  for (let i = 0; i < clean.length; i += 2) {
    const byte = parseInt(clean.slice(i, i + 2), 16);
    if (Number.isNaN(byte)) return null;
    bytes.push(byte);
  }
  return bytes;
}

function tryDecodeBase64Like(token: string): { bytes: number[]; kind: 'base64' | 'base64url' } | null {
  const toB64 = (s: string) => {
    let t = s.replace(/-/g, '+').replace(/_/g, '/');
    while (t.length % 4) t += '=';
    return t;
  };
  const variants: { s: string; kind: 'base64' | 'base64url' }[] = [];
  variants.push({ s: toB64(token), kind: /[-_]/.test(token) ? 'base64url' : 'base64' });
  variants.push({ s: token, kind: 'base64' });
  if (token.startsWith('.')) variants.push({ s: toB64(token.slice(1)), kind: /[-_]/.test(token) ? 'base64url' : 'base64' });
  // Avoid removing all dots; JWT-like tokens should not be coerced to base64 as a whole
  for (const a of variants) {
    try {
      const bin = atob(a.s) as unknown as string;
      const bytes = Array.from(bin as string).map((ch: string) => ch.charCodeAt(0) & 0xff);
      return { bytes, kind: a.kind };
    } catch {}
  }
  return null;
}


// Serial correlation averaged per-token (avoid cross-token boundary artifacts)
function serialCorrelationPerTokenAverage(byteTokens: number[][]): number {
  let weightedAbs = 0;
  let totalBits = 0;
  for (const bytes of byteTokens) {
    const bits = bytesToBits(bytes);
    if (bits.length < 2) continue;
    const corr = serialCorrelation(bits);
    weightedAbs += Math.abs(corr) * bits.length;
    totalBits += bits.length;
  }
  return totalBits > 0 ? (weightedAbs / totalBits) : 0;
}

function decodeTokenToBytes(token: string): { bytes: number[]; encoding: 'hex' | 'base64' | 'base64url' | 'raw' } {
  // Attempt segmented base64/base64url decoding for dot-separated tokens
  if (token.includes('.')) {
    const parts = token.split('.').filter(p => p.length > 0);
    if (parts.length >= 2) {
      const decodedParts: number[][] = [];
      let kind: 'base64' | 'base64url' = 'base64';
      let ok = true;
      for (const p of parts) {
        const maybe = tryDecodeBase64Like(p);
        if (!maybe) { ok = false; break; }
        decodedParts.push(maybe.bytes);
        // If any part looked base64url, keep that label
        if (maybe.kind === 'base64url') kind = 'base64url';
      }
      if (ok) {
        const joined: number[] = [];
        for (const arr of decodedParts) joined.push(...arr);
        return { bytes: joined, encoding: kind };
      }
    }
  }

  // Try whole-string hex or base64-like
  const hex = tryDecodeHex(token);
  if (hex) return { bytes: hex, encoding: 'hex' };
  const b64 = tryDecodeBase64Like(token);
  if (b64) return { bytes: b64.bytes, encoding: b64.kind };
  return { bytes: stringToUtf8Bytes(token), encoding: 'raw' };
}

function bytesToBits(bytes: number[]): number[] {
  const bits: number[] = [];
  for (const byte of bytes) {
    for (let j = 7; j >= 0; j--) bits.push((byte >> j) & 1);
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
function calculatePerPositionMinEntropyBytes(byteTokens: number[][]): { totalEntropy: number, positionData: Array<{ position: number, entropy: number, mostCommonChar: string, frequency: number, coverage?: number }> } {
  if (byteTokens.length === 0) return { totalEntropy: 0, positionData: [] };
  const maxLen = Math.max(...byteTokens.map(t => t.length));
  if (maxLen <= 0) return { totalEntropy: 0, positionData: [] };
  let totalMinEntropy = 0;
  const positionData: Array<{ position: number, entropy: number, mostCommonChar: string, frequency: number, coverage?: number }> = [];

  for (let pos = 0; pos < maxLen; pos++) {
    const freq = new Map<number, number>();
    let contributors = 0;
    for (const bytes of byteTokens) {
      const v = bytes[pos];
      if (v === undefined) continue;
      contributors++;
      freq.set(v, (freq.get(v) || 0) + 1);
    }
    if (contributors === 0) continue;
    let maxCount = 0;
    let mostCommonVal = 0;
    for (const [val, count] of freq) {
      if (count > maxCount) { maxCount = count; mostCommonVal = val; }
    }
    const maxProb = maxCount / contributors;
    const posMinEntropy = -Math.log2(maxProb);
    positionData.push({ position: pos, entropy: posMinEntropy, mostCommonChar: mostCommonVal.toString(16).padStart(2, '0'), frequency: maxProb, coverage: contributors / byteTokens.length });
    totalMinEntropy += posMinEntropy;
  }
  return { totalEntropy: totalMinEntropy, positionData };
}

// Per-position min-entropy on raw token characters (no decoding)
function calculatePerPositionCharEntropyRaw(tokens: string[]): Array<{ position: number, entropy: number, normalizedEntropy: number, mostCommonChar: string, frequency: number, coverage: number }> {
  if (tokens.length === 0) return [];
  const maxLen = Math.max(...tokens.map(t => t.length));
  const results: Array<{ position: number, entropy: number, normalizedEntropy: number, mostCommonChar: string, frequency: number, coverage: number }> = [];
  for (let pos = 0; pos < maxLen; pos++) {
    const freq = new Map<string, number>();
    let contributors = 0;
    for (const tok of tokens) {
      const ch = tok[pos];
      if (ch === undefined) continue;
      contributors++;
      freq.set(ch, (freq.get(ch) || 0) + 1);
    }
    if (contributors === 0) continue;
    let mostChar = '';
    let maxCount = 0;
    for (const [ch, c] of freq) {
      if (c > maxCount) { maxCount = c; mostChar = ch; }
    }
    const maxProb = maxCount / contributors;
    const entropy = -Math.log2(maxProb);
    const alphabetSize = Math.max(1, freq.size);
    const maxAchievable = Math.log2(Math.min(contributors, alphabetSize));
    const normalizedEntropy = maxAchievable > 0 ? Math.min(1, Math.max(0, entropy / maxAchievable)) : 0;
    results.push({ position: pos, entropy, normalizedEntropy, mostCommonChar: mostChar, frequency: maxProb, coverage: contributors / tokens.length });
  }
  return results;
}

// Chi-squared test for uniformity
function erfc(x: number): number {
  const z = Math.abs(x);
  const t = 1 / (1 + 0.5 * z);
  const tau = t * Math.exp(
    -z * z -
      1.26551223 +
      1.00002368 * t +
      0.37409196 * t * t +
      0.09678418 * t ** 3 -
      0.18628806 * t ** 4 +
      0.27886807 * t ** 5 -
      1.13520398 * t ** 6 +
      1.48851587 * t ** 7 -
      0.82215223 * t ** 8 +
      0.17087277 * t ** 9
  );
  return x >= 0 ? tau : 2 - tau;
}

function chiSquaredTest(bits: number[]): number {
  if (bits.length < 100) return 1.0; // Not enough data

  const observed0 = bits.filter(b => b === 0).length;
  const observed1 = bits.filter(b => b === 1).length;
  const expected = bits.length / 2;

  const chiSq = Math.pow(observed0 - expected, 2) / expected +
                Math.pow(observed1 - expected, 2) / expected;
  const pValue = erfc(Math.sqrt(chiSq / 2));
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
function runsTest(bits: number[]): { p: number, applicable: boolean } {
  if (bits.length < 100) return { p: 1.0, applicable: false };

  const n0 = bits.filter(b => b === 0).length;
  const n1 = bits.filter(b => b === 1).length;
  const n = bits.length;
  if (n === 0) return { p: 1.0, applicable: false };

  // NIST precondition: proportion of ones close to 0.5
  const pi = n1 / n;
  const tau = 2 / Math.sqrt(n);
  if (Math.abs(pi - 0.5) >= tau) {
    // Not applicable due to bias; don't flag as fail
    return { p: 1.0, applicable: false };
  }

  // Count runs
  let runs = 1;
  for (let i = 1; i < n; i++) {
    if (bits[i] !== bits[i - 1]) runs++;
  }

  // Expected runs and variance under null hypothesis
  const expectedRuns = (2 * n0 * n1) / n + 1;
  const variance = (2 * n0 * n1 * (2 * n0 * n1 - n)) / (n * n * (n - 1));
  if (variance === 0) return { p: 1.0, applicable: false };

  const z = (runs - expectedRuns) / Math.sqrt(variance);
  const pValue = 2 * (1 - normalCDF(Math.abs(z)));
  return { p: Math.max(0, Math.min(1, pValue)), applicable: true };
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

// ========== SP 800-22 (subset) helpers on raw-string basis ==========

function charStringToBitsRaw(s: string): number[] {
  const bits: number[] = [];
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i) & 0xff; // 8-bit
    for (let b = 7; b >= 0; b--) bits.push((c >> b) & 1);
  }
  return bits;
}

// SP 800-22 Frequency (Monobit)
function sp22FrequencyMonobit(bits: number[]): { p: number, applicable: boolean } {
  const n = bits.length;
  if (n < 100) return { p: 1.0, applicable: false };
  let s = 0;
  for (let i = 0; i < n; i++) s += bits[i] === 1 ? 1 : -1;
  const sObs = Math.abs(s) / Math.sqrt(n);
  const p = erfc(sObs / Math.SQRT2);
  return { p: Math.max(0, Math.min(1, p)), applicable: true };
}

// Regularized upper incomplete gamma Q(s, x) via series/continued fraction
function gammaincUpperRegularized(s: number, x: number): number {
  if (x <= 0) return 1;
  if (x < s + 1) {
    // Use series for P(s,x), then Q = 1 - P
    let sum = 1 / s;
    let term = sum;
    for (let n = 1; n < 1000; n++) {
      term *= x / (s + n);
      sum += term;
      if (term < sum * 1e-12) break;
    }
    const lnGammaS = lnGamma(s);
    const P = sum * Math.exp(s * Math.log(x) - x - lnGammaS);
    return 1 - Math.min(1, Math.max(0, P));
  } else {
    // Continued fraction for Q(s,x)
    const lnGammaS = lnGamma(s);
    let a0 = 1; let a1 = x - s + 1; let b0 = 0; let b1 = 1;
    let fac = 1 / a1;
    let g = b1 * fac;
    let gold = 0;
    for (let n = 1; n < 1000; n++) {
      const an = n * (s - n);
      a0 = (a1 + a0 * an) as number;
      b0 = (b1 + b0 * an) as number;
      const aNew = (x - s + 2 * n + 1) * a0 + an * a1;
      const bNew = (x - s + 2 * n + 1) * b0 + an * b1;
      a1 = aNew; b1 = bNew;
      if (b1 !== 0) {
        fac = 1 / b1;
        g = a1 * fac;
        if (Math.abs((g - gold) / g) < 1e-12) break;
        gold = g;
      }
    }
    const Q = Math.exp(s * Math.log(x) - x - lnGammaS) * g;
    return Math.min(1, Math.max(0, Q));
  }
}

// (removed approxGamma; use lnGamma directly)

function lnGamma(z: number): number {
  const p = [
    676.5203681218851,
    -1259.1392167224028,
    771.32342877765313,
    -176.61502916214059,
    12.507343278686905,
    -0.13857109526572012,
    9.9843695780195716e-6,
    1.5056327351493116e-7,
  ];
  if (z < 0.5) {
    return Math.log(Math.PI) - Math.log(Math.sin(Math.PI * z)) - lnGamma(1 - z);
  }
  z -= 1;
  let x = 0.99999999999980993;
  for (let i = 0; i < p.length; i++) x += (p[i] as number) / (z + i + 1);
  const t = z + p.length - 0.5;
  return 0.5 * Math.log(2 * Math.PI) + (z + 0.5) * Math.log(t) - t + Math.log(x);
}

function chiSquareUpperTailPValue(chi2: number, df: number): number {
  const s = df / 2;
  const x = chi2 / 2;
  return gammaincUpperRegularized(s, x);
}

// SP 800-22 Block Frequency test
function sp22BlockFrequency(bits: number[], M: number = 128): { p: number, applicable: boolean, blocks: number } {
  const n = bits.length;
  const N = Math.floor(n / M);
  if (N < 1) return { p: 1.0, applicable: false, blocks: 0 };
  let chi2 = 0;
  for (let i = 0; i < N; i++) {
    let sum = 0;
    for (let j = 0; j < M; j++) sum += (bits[i * M + j] ?? 0);
    const pi = sum / M;
    chi2 += 4 * M * Math.pow(pi - 0.5, 2);
  }
  const p = chiSquareUpperTailPValue(chi2, N);
  return { p, applicable: true, blocks: N };
}

// Aggregate per-token p-values via median; report pass rate at alpha
function aggregatePValues(pvalues: number[], alpha: number): { median: number, passRate: number } {
  if (pvalues.length === 0) return { median: 1.0, passRate: 1.0 };
  const sorted = [...pvalues].sort((a,b)=>a-b);
  const median = sorted[Math.floor(sorted.length/2)] ?? 1.0;
  const passRate = pvalues.filter(p => p >= alpha).length / pvalues.length;
  return { median, passRate };
}

// SP 800-22 Serial test (m=2)
function sp22SerialM2(bits: number[]): { p1: number, p2: number, applicable: boolean } {
  const n = bits.length;
  if (n < 1000) return { p1: 1.0, p2: 1.0, applicable: false };
  function psi2(m: number): number {
    if (m <= 0) return 0;
    const k = 1 << m;
    const counts: number[] = new Array<number>(k).fill(0);
    // Build overlapping m-bit patterns with wrap-around
    let pattern = 0;
    for (let i = 0; i < m; i++) pattern = (pattern << 1) | (bits[i] || 0);
    counts[pattern]!++;
    for (let i = m; i < n + m - 1; i++) {
      pattern = ((pattern << 1) & (k - 1)) | (bits[i % n] || 0);
      counts[pattern]!++;
    }
    let sum = 0;
    for (let i = 0; i < k; i++) sum += (counts[i]! * counts[i]!);
    return (k * sum) / n - n;
  }
  const psim2 = psi2(2);
  const psim1 = psi2(1);
  const psim0 = psi2(0);
  const delta1 = psim2 - psim1;
  const delta2 = psim1 - psim0;
  const df1 = 1 << (2 - 1); // 2^(m-1) = 2
  const df2 = 1 << (2 - 2); // 2^(m-2) = 1
  const p1 = chiSquareUpperTailPValue(delta1, df1);
  const p2 = chiSquareUpperTailPValue(delta2, df2);
  return { p1: Math.max(0, Math.min(1, p1)), p2: Math.max(0, Math.min(1, p2)), applicable: true };
}

// SP 800-22 Approximate Entropy (m=2)
function sp22ApproxEntropy(bits: number[], m: number = 2): { p: number, applicable: boolean } {
  const n = bits.length;
  if (n < 10000) return { p: 1.0, applicable: false };
  function phi(mm: number): number {
    const k = 1 << mm;
    const counts: number[] = new Array<number>(k).fill(0);
    let pattern = 0;
    for (let i = 0; i < mm; i++) pattern = (pattern << 1) | (bits[i] || 0);
    counts[pattern]!++;
    for (let i = mm; i < n + mm - 1; i++) {
      pattern = ((pattern << 1) & (k - 1)) | (bits[i % n] || 0);
      counts[pattern]!++;
    }
    let sum = 0;
    for (let i = 0; i < k; i++) {
      const p = (counts[i]! / n);
      if (p > 0) sum += p * Math.log(p);
    }
    return sum;
  }
  const phi_m = phi(m);
  const phi_m1 = phi(m + 1);
  const apEn = phi_m - phi_m1;
  const X = 2 * n * (Math.log(2) - apEn);
  // df = 2^(m) - 1 but NIST uses s = 2^(m-1) in igamc(s, X/2) for p-value mapping
  const s = 1 << (m - 1);
  const p = gammaincUpperRegularized(s, X / 2);
  return { p: Math.max(0, Math.min(1, p)), applicable: true };
}

// SP 800-22 Cumulative Sums (forward/backward)
function sp22CumulativeSums(bits: number[]): { p: number, applicable: boolean } {
  const n = bits.length;
  if (n < 1000) return { p: 1.0, applicable: false };
  const toSigns = (arr: number[]) => arr.map(b => (b === 1 ? 1 : -1));
  const signs = toSigns(bits);
  const zFor = (arr: number[]) => {
    let s = 0;
    let z = 0;
    for (let i = 0; i < arr.length; i++) {
      s += arr[i] || 0;
      const a = Math.abs(s);
      if (a > z) z = a;
    }
    return z;
  };
  const zf = zFor(signs);
  const zb = zFor([...signs].reverse());
  const calcP = (z: number): number => {
    if (z === 0) return 1.0;
    const sqrtN = Math.sqrt(n);
    let sum1 = 0;
    const start1 = Math.floor((-n / z + 1) / 4);
    const end1 = Math.floor((n / z - 1) / 4);
    for (let k = start1; k <= end1; k++) {
      sum1 += normalCDF(((4 * k + 1) * z) / sqrtN) - normalCDF(((4 * k - 1) * z) / sqrtN);
    }
    let sum2 = 0;
    const start2 = Math.floor((-n / z - 3) / 4);
    const end2 = Math.floor((n / z - 1) / 4);
    for (let k = start2; k <= end2; k++) {
      sum2 += normalCDF(((4 * k + 3) * z) / sqrtN) - normalCDF(((4 * k + 1) * z) / sqrtN);
    }
    const p = 1 - sum1 + sum2;
    return Math.max(0, Math.min(1, p));
  };
  const pf = calcP(zf);
  const pb = calcP(zb);
  const p = Math.min(pf, pb);
  return { p, applicable: true };
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

// Bit-level entropy calculation from decoded bytes
function calculateBitEntropyFromBytes(byteTokens: number[][]): { totalBits: number; onesCount: number; zerosCount: number; bitEntropy: number } {
  let onesCount = 0;
  let zerosCount = 0;
  for (const bytes of byteTokens) {
    for (const b of bytes) {
      for (let i = 0; i < 8; i++) ((b >> i) & 1) ? onesCount++ : zerosCount++;
    }
  }
  const totalBits = onesCount + zerosCount;
  if (totalBits === 0) return { totalBits: 0, onesCount: 0, zerosCount: 0, bitEntropy: 0 };
  const pOne = onesCount / totalBits;
  const pZero = 1 - pOne;
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
function analyzeTokens(captures: TokenCapture[], detail: boolean = true): AnalysisResult {
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

  // Character analysis (for display only; byte-level tests drive results)
  const charAnalysis = analyzeCharacters(tokens);

  // Decode all tokens to bytes and bits (only if Security Analysis is enabled)
  let decoded: { bytes: number[]; encoding: string }[] = [];
  let byteTokens: number[][] = [];
  let allBits: number[] = [];
  let bitAnalysis: any = { totalBits: 0, onesCount: 0, zerosCount: 0, bitEntropy: 0 };

  if (detail) {
    decoded = tokens.map(t => decodeTokenToBytes(t));
    byteTokens = decoded.map(d => d.bytes);
    // Build full bitstream across tokens (do not strip common prefixes)
    for (const bytes of byteTokens) allBits.push(...bytesToBits(bytes));
    // Bit analysis (byte-true)
    bitAnalysis = calculateBitEntropyFromBytes(byteTokens);
  }

  const totalBits = allBits.length;
  const avgBitsPerToken = detail ? (totalBits / tokens.length) : 0;

  // Security Analysis heavy computations - only when detail=true
  let shannonEntropyPerBit = 0;
  let minEntropyWholeToken = 0;
  let perPositionResult: any = { totalEntropy: 0, positionData: [] };
  let perPositionMinEntropy = 0;
  let perPositionMinEntropyPerBit = 0;

  if (detail) {
    // Shannon entropy per bit
    const bit0Count = allBits.filter(b => b === 0).length;
    const p0 = totalBits ? bit0Count / totalBits : 0;
    const p1 = 1 - p0;
    shannonEntropyPerBit = p0 > 0 && p1 > 0 ? -(p0 * Math.log2(p0) + p1 * Math.log2(p1)) : 0;

    // Whole-token min-entropy (only meaningful if duplicates exist)
    minEntropyWholeToken = calculateMinEntropy(tokens);

    // Per-position min-entropy using bytes (now computed up to minimum common length)
    perPositionResult = calculatePerPositionMinEntropyBytes(byteTokens);
    perPositionMinEntropy = perPositionResult.totalEntropy;
    perPositionMinEntropyPerBit = avgBitsPerToken ? (perPositionResult.totalEntropy / avgBitsPerToken) : 0;
  }
  // Security assessment accumulators
  const issues: string[] = [];
  const warnings: string[] = [];
  const strengths: string[] = [];

  // Security Analysis metrics - only computed when detail=true
  let minEntropyPerBit = 0;
  let effectiveSecurityBits = 0;
  let chiSquaredPValue = 1.0;
  let serialCorr = 0;
  let runsTestPValue = 1.0;
  let lzCompressionRatio = 1.0;
  let estimatedEntropyRate = 0;
  let collisionAnalysis: any = { exactDuplicates: 0, nearDuplicates: 0, averageHammingDistance: 0 };

  if (detail) {
    // Bit-bias min-entropy per bit across all bits
    const bit0Count = allBits.filter(b => b === 0).length;
    const p0 = totalBits ? bit0Count / totalBits : 0;
    const p1 = 1 - p0;
    const pMax = Math.max(p0, p1);
    minEntropyPerBit = pMax > 0 ? -Math.log2(pMax) : 0;

    // Effective security bits: avoid sample-size cap when no duplicates
    const estimators: number[] = [];
    // Always include bit-bias estimator across all bits
    estimators.push(minEntropyPerBit * avgBitsPerToken);
    // Include per-position bytes estimator only if fixed-length
    if (perPositionMinEntropy !== undefined) estimators.push(perPositionMinEntropy);
    // Include whole-token min-entropy only if duplicates exist
    if (duplicateCount > 0) estimators.push(minEntropyWholeToken);
    effectiveSecurityBits = Math.min(...estimators);

    // Prepare per-token bit arrays for aggregated tests
    const perTokenBits = byteTokens.map(b => bytesToBits(b)).filter(b => b.length >= 100);
    // Chi-squared: aggregate per-token p-values (median), to avoid cross-token artifacts
    const chiPs = perTokenBits.map(b => chiSquaredTest(b)).filter(p => !Number.isNaN(p));
    const chiSorted = [...chiPs].sort((a,b)=>a-b);
    chiSquaredPValue = chiSorted.length > 0 ? (chiSorted[Math.floor(chiSorted.length/2)] ?? 1.0) : 1.0;

    // Serial correlation (per-token average over full tokens)
    serialCorr = serialCorrelationPerTokenAverage(byteTokens);

    // Runs test: compute per-token and aggregate to reduce long-stream bias
    const runsResults = perTokenBits.map(b => runsTest(b));
    const applicableRuns = runsResults.filter(r => r.applicable).map(r => r.p);
    const runsSorted = [...applicableRuns].sort((a,b)=>a-b);
    runsTestPValue = runsSorted.length > 0 ? (runsSorted[Math.floor(runsSorted.length/2)] ?? 1.0) : 1.0;

    // LZ compression-based entropy estimate
    const lzEntropy = lzEntropyEstimate(allBits);
    lzCompressionRatio = shannonEntropyPerBit > 1e-9 ? (lzEntropy / shannonEntropyPerBit) : 1;
    estimatedEntropyRate = lzEntropy;

    // Collision analysis
    collisionAnalysis = analyzeCollisions(tokens);
  }

  // === NIST-style Security Assessment based on Min-Entropy (only when Security Analysis is enabled) ===

  const recommendedMinimum = 128; // NIST recommendation for session tokens

  if (detail) {
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

  // Data sufficiency notes
  const insufficientBits = totalBits < 100;

  // Chi-squared uniformity test
  if (!insufficientBits && chiSquaredPValue < 0.01) {
    issues.push(`Chi-squared test failed (p=${chiSquaredPValue.toFixed(4)}). Bit distribution is non-uniform.`);
  } else if (!insufficientBits && chiSquaredPValue < 0.05) {
    warnings.push(`Chi-squared test marginal (p=${chiSquaredPValue.toFixed(4)}). Slight non-uniformity detected.`);
  } else {
    strengths.push(`Chi-squared test passed (p=${chiSquaredPValue.toFixed(4)}). Uniform bit distribution.`);
  }

  // Serial correlation test
  const absCorr = Math.abs(serialCorr);
  if (absCorr > 0.5) {
    issues.push(`High serial correlation (${serialCorr.toFixed(3)}). Consecutive bits are dependent.`);
  } else if (absCorr > 0.2) {
    warnings.push(`Moderate serial correlation (${serialCorr.toFixed(3)}). Some bit dependencies present.`);
  } else {
    strengths.push(`Low serial correlation (${serialCorr.toFixed(3)}). Bits are independent.`);
  }

  // Runs test
  if (!insufficientBits && runsTestPValue < 0.01) {
    issues.push(`Runs test failed (p=${runsTestPValue.toFixed(4)}). Non-random run patterns detected.`);
  } else if (!insufficientBits && runsTestPValue < 0.05) {
    warnings.push(`Runs test marginal (p=${runsTestPValue.toFixed(4)}). Possible run pattern issues.`);
  } else {
    strengths.push(`Runs test passed (p=${runsTestPValue.toFixed(4)}). Random run distribution.`);
  }

  // LZ compression entropy
  if (!insufficientBits && lzCompressionRatio > 1.5) {
    issues.push(`High LZ compression ratio (${lzCompressionRatio.toFixed(2)}). Structure detected in data.`);
  } else if (!insufficientBits && lzCompressionRatio > 1.10) {
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
  }

  // Add partial failure warnings
  warnings.push(...partialFailures);

  // Overall rating: make CRITICAL depend on effective bits or strong failures
  let overallRating: 'CRITICAL' | 'WARNING' | 'GOOD' | 'EXCELLENT';
  if (detail) {
    const insufficientBits = totalBits < 100;
    const severeTestFailure = (!insufficientBits && (Math.abs(serialCorr) > 0.5 || chiSquaredPValue < 0.001 || runsTestPValue < 0.001));
    if (effectiveSecurityBits < 64 || (effectiveSecurityBits < 80 && severeTestFailure)) overallRating = 'CRITICAL';
    else if (warnings.length > 0 || effectiveSecurityBits < 128 || severeTestFailure) overallRating = 'WARNING';
    else if (strengths.length >= 3) overallRating = 'EXCELLENT';
    else overallRating = 'GOOD';
  } else {
    // When Security Analysis is disabled, provide a basic rating based on duplicates and patterns
    if (duplicatePercentage > 10 || sequential.isSequential || hasTimestamps) overallRating = 'CRITICAL';
    else if (duplicatePercentage > 5 || predictabilityScore > 20) overallRating = 'WARNING';
    else overallRating = 'GOOD';
  }

  // === SP 800-22 (subset) on raw-string basis ===
  const alpha = 0.01;
  const rawBitsPerToken = tokens.map(t => charStringToBitsRaw(t));
  const monobitAll = rawBitsPerToken.map(b => sp22FrequencyMonobit(b));
  const runsAll = rawBitsPerToken.map(b => runsTest(b));
  const blockAll = rawBitsPerToken.map(b => sp22BlockFrequency(b, 256));
  const serialAll = rawBitsPerToken.map(b => sp22SerialM2(b));
  const apenAll = rawBitsPerToken.map(b => sp22ApproxEntropy(b, 2));
  const cusumAll = rawBitsPerToken.map(b => sp22CumulativeSums(b));

  const freqApplicable = monobitAll.filter(r => r.applicable);
  const runsApplicable = runsAll.filter(r => r.applicable);
  const blockApplicable = blockAll.filter(r => r.applicable);
  const serialApplicable = serialAll.filter(r => r.applicable);
  const apenApplicable = apenAll.filter(r => r.applicable);
  const cusumApplicable = cusumAll.filter(r => r.applicable);
  const freqP = aggregatePValues(freqApplicable.map(r => r.p), alpha);
  const runsP = aggregatePValues(runsApplicable.map(r => r.p), alpha);
  const blockP = aggregatePValues(blockApplicable.map(r => r.p), alpha);
  const serialP = aggregatePValues(serialApplicable.map(r => Math.min(r.p1, r.p2)), alpha);
  const apenP = aggregatePValues(apenApplicable.map(r => r.p), alpha);
  const cusumP = aggregatePValues(cusumApplicable.map(r => r.p), alpha);

  const statisticalTests = {
    basis: 'raw_string' as const,
    alpha,
    tests: [
      {
        name: 'Frequency (Monobit)',
        applicableCount: freqApplicable.length,
        passCount: Math.round(freqP.passRate * freqApplicable.length),
        passRate: freqP.passRate,
        medianP: freqP.median,
        pValues: monobitAll.map(r => r.applicable ? r.p : null)
      },
      {
        name: 'Runs',
        applicableCount: runsApplicable.length,
        passCount: Math.round(runsP.passRate * runsApplicable.length),
        passRate: runsP.passRate,
        medianP: runsP.median,
        pValues: runsAll.map(r => r.applicable ? r.p : null)
      },
      {
        name: 'Block Frequency (M=256)',
        applicableCount: blockApplicable.length,
        passCount: Math.round(blockP.passRate * blockApplicable.length),
        passRate: blockP.passRate,
        medianP: blockP.median,
        pValues: blockAll.map(r => r.applicable ? r.p : null)
      },
      {
        name: 'Serial (m=2)',
        applicableCount: serialApplicable.length,
        passCount: Math.round(serialP.passRate * serialApplicable.length),
        passRate: serialP.passRate,
        medianP: serialP.median,
        pValues: serialAll.map(r => r.applicable ? Math.min(r.p1, r.p2) : null)
      },
      {
        name: 'Approximate Entropy (m=2)',
        applicableCount: apenApplicable.length,
        passCount: Math.round(apenP.passRate * apenApplicable.length),
        passRate: apenP.passRate,
        medianP: apenP.median,
        pValues: apenAll.map(r => r.applicable ? r.p : null)
      },
      {
        name: 'Cumulative Sums (for/back)',
        applicableCount: cusumApplicable.length,
        passCount: Math.round(cusumP.passRate * cusumApplicable.length),
        passRate: cusumP.passRate,
        medianP: cusumP.median,
        pValues: cusumAll.map(r => r.applicable ? r.p : null)
      },
    ],
  };

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
      perPositionData: detail ? perPositionResult.positionData : undefined,
      perPositionRawData: calculatePerPositionCharEntropyRaw(tokens)
    },
    collisionAnalysis,
    security: {
      overallRating,
      issues,
      warnings,
      strengths,
      effectiveBits: effectiveSecurityBits,
      recommendedMinimum
    },
    statisticalTests
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
  pauseOn429?: boolean;
  respectRetryAfter?: boolean;
  maxPauseMs?: number;
  require2xx?: boolean;
  non2xxPauseMs?: number;
  allowedStatusCodes?: number[];
  skipUntilAllowedStatus?: boolean;
  requireTokenMatch?: boolean;
}

interface CollectionConfig {
  httpRequest: string;
  parameterName: string;
  count: number;
  rateLimit?: RateLimitConfig;
  runId?: string;
}

export type API = DefineAPI<{
  test: () => string;
  startCollection: (config: CollectionConfig) => Promise<TokenCapture[]>;
  getTokens: () => TokenCapture[];
  analyzeTokens: (opts?: { securityAnalysis?: boolean }) => AnalysisResult;
  exportCSV: () => string;
  exportJSON: () => string;
  cancelCollection: (runId?: string) => boolean;
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
      const thisRunId = config.runId || `${Date.now()}-${Math.random().toString(36).slice(2)}`;
      activeRunId = thisRunId;
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

            // Check for rate limit or disallowed status handling
            if (statusCode === 429 && config.rateLimit?.enabled) {
              const rl = config.rateLimit;
              const skipOn429 = rl.skipUntilAllowedStatus ?? true;
              if (skipOn429) {
                // Signal outer loop to skip counting without delay
                throw new Error(`SKIP_STATUS:429`);
              }
            }
            // Enforce allowed status codes (default: 2xx and 302)
            const rl = config.rateLimit;
            const allowed = rl?.allowedStatusCodes ?? (rl?.require2xx ?? true
              ? [200,201,202,203,204,205,206,302]
              : undefined);
            const skipUntilAllowed = rl?.skipUntilAllowedStatus ?? true;
            if (allowed && !allowed.includes(statusCode)) {
              if (skipUntilAllowed) {
                throw new Error(`SKIP_STATUS:${statusCode}`);
              }
            }

            // Get response data
            const responseBody = response.response.getBody()?.toString() || '';
            const responseHeaders = response.response.getHeaders() || {};

            // Extract token
            const result = extractTokenFromResponse(responseBody, responseHeaders, config.parameterName);

            // Enforce token presence if required (default off when no rateLimit provided)
            const requireTokenMatch = config.rateLimit?.requireTokenMatch ?? false;
            if (requireTokenMatch && (!result.token || result.token.length === 0)) {
              // Skip counting and do not record
              throw new Error('SKIP_NOTOKEN');
            }

            // Build capture only when token exists or matching not required
            return {
              token: result.token ?? 'Not found',
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

        // All retries failed: return an error capture so callers can display feedback
        const errorMessage = lastError instanceof Error ? lastError.message : String(lastError);
        return {
          token: 'Request failed',
          requestSent: requestStr,
          responseReceived: `Error: ${errorMessage}\nAttempted URL: ${baseUrl + path}\nMethod: ${method || 'GET'}\nRequest #${requestNum}`,
          extractedFrom: `Error: ${errorMessage}`
        };
      };

      // Preflight: single request to ensure token can be extracted; if not, return early with the capture
      const pre = await sendRequestWithRetry(1);
      const tokenOk = pre.token && pre.token !== 'Not found' && !pre.token.startsWith('Request failed');
      tokenCaptures.push(pre);
      if (!tokenOk) {
        if (activeRunId === thisRunId) activeRunId = null;
        cancelledRuns.delete(thisRunId);
        return tokenCaptures;
      }

      // Collect tokens by sending real requests
      const rateLimit = config.rateLimit;
      let collected = 1; // preflight already added
      while (collected < config.count) {
        if (cancelledRuns.has(thisRunId)) break;
        try {
          const capture = await sendRequestWithRetry(collected + 1);
          tokenCaptures.push(capture);
          collected++;

          // Apply rate limiting if enabled
          if (rateLimit?.enabled) {
            const isLastInBatch = collected % rateLimit.requestsPerBatch === 0;
            const isNotDone = collected < config.count;
            if (isLastInBatch && isNotDone) {
              const delay = rateLimit.delayBetweenBatches; const step = Math.max(50, Math.min(500, Math.floor(delay/10))); let waited=0;
              while (waited < delay) { if (cancelledRuns.has(thisRunId)) break; await new Promise(r=>setTimeout(r,step)); waited+=step; }
            } else if (isNotDone) {
              const delay = 100; const step = 50; let waited=0;
              while (waited < delay) { if (cancelledRuns.has(thisRunId)) break; await new Promise(r=>setTimeout(r,step)); waited+=step; }
            }
          } else {
            if (collected < config.count) {
              const delay = 100; const step = 50; let waited=0;
              while (waited < delay) { if (cancelledRuns.has(thisRunId)) break; await new Promise(r=>setTimeout(r,step)); waited+=step; }
            }
          }
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          if (cancelledRuns.has(thisRunId)) break;
          if (msg.startsWith('SKIP_STATUS:')) {
            // Do not increment collected or record a capture; retry immediately (batch pacing still applies)
            continue;
          }
          if (msg === 'SKIP_NOTOKEN') {
            // Do not count or record
            continue;
          }
          if (msg.startsWith('SKIP_STATUS:')) {
            continue;
          }
          // For any other unexpected error, do not count or record
          continue;
        }
      }
      if (activeRunId === thisRunId) activeRunId = null;
      cancelledRuns.delete(thisRunId);
    } catch (error) {
      // Parsing failed: do not record any capture to keep "collected" strictly token-bearing
    }
    
    return tokenCaptures;
  });
  
  sdk.api.register("getTokens", () => {
    return tokenCaptures;
  });

  sdk.api.register("analyzeTokens", (_sdk, opts?: { securityAnalysis?: boolean, detail?: boolean }) => {
    // Accept legacy 'detail' for compatibility, prefer 'securityAnalysis'
    const security = !!(opts && (opts.securityAnalysis ?? opts.detail));
    return analyzeTokens(tokenCaptures, security);
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
    const analysis = analyzeTokens(tokenCaptures, true);
    return JSON.stringify({
      timestamp: new Date().toISOString(),
      tokenCaptures,
      analysis
    }, null, 2);
  });

  sdk.api.register("cancelCollection", (_sdk, runId?: string) => {
    const id = runId || activeRunId;
    if (!id) return false;
    cancelledRuns.add(id);
    return true;
  });
}
