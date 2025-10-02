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
  security: {
    overallRating: 'CRITICAL' | 'WARNING' | 'GOOD' | 'EXCELLENT';
    issues: string[];
    warnings: string[];
    strengths: string[];
  };
}

let tokenCaptures: TokenCapture[] = [];

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
      security: { overallRating: 'CRITICAL', issues: [`${errorType}:${errorMessage}`], warnings: [], strengths: [] }
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

  // Security assessment
  const issues: string[] = [];
  const warnings: string[] = [];
  const strengths: string[] = [];

  // Entropy checks
  if (entropy < 3.0) issues.push(`Very low entropy (${entropy.toFixed(2)}). Tokens are highly predictable.`);
  else if (entropy < 4.0) warnings.push(`Low entropy (${entropy.toFixed(2)}). Moderate predictability.`);
  else if (entropy >= 4.5) strengths.push(`Good entropy (${entropy.toFixed(2)}). High randomness.`);

  // Duplicate checks
  if (duplicatePercentage > 10) issues.push(`${duplicatePercentage.toFixed(1)}% duplicate tokens. Poor randomness.`);
  else if (duplicatePercentage > 5) warnings.push(`${duplicatePercentage.toFixed(1)}% duplicate tokens.`);
  else if (duplicatePercentage < 2) strengths.push(`Very few duplicates (${duplicatePercentage.toFixed(1)}%).`);

  // Sequential checks
  if (sequential.isSequential) issues.push('Sequential pattern detected. Tokens are predictable.');
  else strengths.push('No sequential patterns detected.');

  // Timestamp checks
  if (hasTimestamps) issues.push('Timestamp-based tokens detected. Highly predictable.');

  // Bit entropy checks
  if (bitAnalysis.bitEntropy < 0.9) warnings.push(`Low bit-level entropy (${bitAnalysis.bitEntropy.toFixed(3)}). Biased bit distribution.`);
  else if (bitAnalysis.bitEntropy > 0.99) strengths.push(`Excellent bit-level entropy (${bitAnalysis.bitEntropy.toFixed(3)}).`);

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
    security: {
      overallRating,
      issues,
      warnings,
      strengths
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

    const headers = ['Index', 'Token', 'Length', 'Extracted From'];
    const rows = tokenCaptures.map((capture, index) => [
      index + 1,
      capture.token,
      capture.token.length,
      capture.extractedFrom
    ]);

    const csv = [
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
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