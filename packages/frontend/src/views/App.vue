<script setup lang="ts">
import Button from "primevue/button";
import InputNumber from "primevue/inputnumber";
import InputText from "primevue/inputtext";
import Textarea from "primevue/textarea";
import Card from "primevue/card";
import Message from "primevue/message";
import ProgressBar from "primevue/progressbar";
import Dialog from "primevue/dialog";
import Checkbox from "primevue/checkbox";
import { ref, Directive, onMounted, nextTick } from "vue";
import { useSDK } from "../plugins/sdk";
import HelpDocs from "./HelpDocs.vue";
import { Chart, BarController, BarElement, CategoryScale, LinearScale, Title, Tooltip, Legend } from 'chart.js';

// Register Chart.js components
Chart.register(BarController, BarElement, CategoryScale, LinearScale, Title, Tooltip, Legend);

// Define tooltip directive with better handling
const vTooltip: Directive = {
  mounted(el, binding) {
    const tooltipText = binding.value;

    // Create tooltip element
    const tooltip = document.createElement('div');
    tooltip.className = 'custom-tooltip';
    tooltip.textContent = tooltipText;
    tooltip.style.cssText = `
      position: absolute;
      background: rgba(0, 0, 0, 0.9);
      color: white;
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 13px;
      white-space: normal;
      max-width: 300px;
      z-index: 9999;
      pointer-events: none;
      opacity: 0;
      transition: opacity 0.2s;
      bottom: 100%;
      left: 50%;
      transform: translateX(-50%) translateY(-8px);
      box-shadow: 0 4px 6px rgba(0,0,0,0.3);
    `;

    el.style.position = 'relative';
    el.appendChild(tooltip);

    el.addEventListener('mouseenter', () => {
      tooltip.style.opacity = '1';
    });

    el.addEventListener('mouseleave', () => {
      tooltip.style.opacity = '0';
    });
  }
};

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

const sdk = useSDK();
const message = ref("Ready");
const tokenCount = ref(10);
const captures = ref<TokenCapture[]>([]);
const isCollecting = ref(false);
const httpRequest = ref("");
const parameterName = ref("");
const selectedCapture = ref<TokenCapture | null>(null);
const analysis = ref<AnalysisResult | null>(null);
const showTokensDialog = ref(false);
const showTokenDetailsDialog = ref(false);
const showHelp = ref(false);
const showResponsePreview = ref(false);
const showTechnicalDetailsDialog = ref(false);
const previewResponse = ref<{body: string, headers: Record<string, string | string[]>} | null>(null);
const extractableFields = ref<Array<{name: string, value: string, source: string}>>([]);
const positionEntropyCanvas = ref<HTMLCanvasElement | null>(null);
let positionEntropyChart: Chart | null = null;

// Rate limiting configuration
const rateLimitEnabled = ref(false);
const requestsPerBatch = ref(10);
const delayBetweenBatches = ref(5000);
const retryOn429 = ref(true);
const maxRetries = ref(3);
const retryDelay = ref(1000);
const backoffMultiplier = ref(2);

const extractAllFields = (responseBody: string, headers: Record<string, string | string[]>) => {
  const fields: Array<{name: string, value: string, source: string}> = [];
  const seen = new Set<string>();

  // Common token parameter names to look for
  const commonParams = [
    'token', 'csrf', 'csrf_token', 'csrfToken', 'authenticity_token',
    'session', 'sessionId', 'session_id', 'sessionid', 'SESSIONID',
    'sid', 'id', 'nonce', 'state', 'code', 'auth', 'authToken',
    'access_token', 'accessToken', 'refresh_token', 'api_key', 'apiKey'
  ];

  // Extract from Set-Cookie headers
  for (const [name, value] of Object.entries(headers)) {
    if (name.toLowerCase() === 'set-cookie') {
      const cookies = Array.isArray(value) ? value : [value];
      cookies.forEach(cookie => {
        const match = cookie.match(/^([^=]+)=/);
        if (match && match[1]) {
          const cookieName = match[1].trim();
          if (!seen.has(cookieName) && commonParams.some(p => cookieName.toLowerCase().includes(p))) {
            fields.push({ name: cookieName, value: cookie.substring(0, 50), source: 'Set-Cookie' });
            seen.add(cookieName);
          }
        }
      });
    }
  }

  // Extract from JSON
  try {
    const json = JSON.parse(responseBody);
    const extractFromJson = (obj: any, prefix = '') => {
      for (const [key, val] of Object.entries(obj)) {
        const fullKey = prefix ? `${prefix}.${key}` : key;
        if (typeof val === 'string' || typeof val === 'number') {
          if (!seen.has(fullKey) && commonParams.some(p => key.toLowerCase().includes(p))) {
            fields.push({ name: fullKey, value: String(val).substring(0, 50), source: 'JSON body' });
            seen.add(fullKey);
          }
        } else if (typeof val === 'object' && val !== null && !Array.isArray(val)) {
          extractFromJson(val, fullKey);
        }
      }
    };
    extractFromJson(json);
  } catch {}

  return fields;
};


const startCollection = async () => {
  if (!httpRequest.value.trim()) {
    message.value = "Error: HTTP request required";
    return;
  }

  // If no parameter name, do a test request to detect possible parameters
  if (!parameterName.value.trim()) {
    isCollecting.value = true;
    message.value = "Detecting possible parameters...";

    try {
      const config = {
        httpRequest: httpRequest.value,
        parameterName: "token", // dummy parameter for first request
        count: 1
      };

      const result = await sdk.backend.startCollection(config);
      if (result.length > 0) {
        const capture = result[0];
        const response = capture?.responseReceived || '';
        const headers = capture?.responseHeaders;
        const errorInfo = capture?.extractedFrom || '';

        // Check if request failed with error message
        if (capture?.token.startsWith('Request failed') || capture?.token.startsWith('Failed to send')) {
          // Store the failed capture so user can see it in "View All Responses"
          captures.value = [capture];
          const errorMessage = errorInfo || capture?.token || 'Unknown error';
          message.value = `Request failed: ${errorMessage}`;
          isCollecting.value = false;
          return;
        }

        // Check if response is empty (but token was extracted without error)
        if (!response || response.trim().length === 0) {
          if (!capture?.token || capture.token.trim().length === 0) {
            message.value = "Request failed: No response received from server. Check your HTTP request.";
            isCollecting.value = false;
            return;
          }
        }

        // Extract all fields from response
        const fields = extractAllFields(response, headers || {});

        if (fields.length > 0) {
          extractableFields.value = fields;
          previewResponse.value = { body: response, headers: headers || {} };
          showResponsePreview.value = true;
          message.value = `Found ${fields.length} extractable fields. Select one to analyze.`;
        } else {
          // Show response anyway even if no fields detected
          previewResponse.value = { body: response, headers: headers || {} };
          showResponsePreview.value = true;
          message.value = "Response loaded. Find and copy the parameter name manually.";
        }
      } else {
        message.value = "Request failed: No response received. Check your HTTP request format and try again.";
      }
      isCollecting.value = false;
      return;
    } catch (error) {
      message.value = "Error during parameter detection";
      isCollecting.value = false;
      return;
    }
  }

  isCollecting.value = true;
  message.value = "Collecting tokens...";
  analysis.value = null;

  try {
    const config = {
      httpRequest: httpRequest.value,
      parameterName: parameterName.value,
      count: tokenCount.value,
      rateLimit: rateLimitEnabled.value ? {
        enabled: true,
        requestsPerBatch: requestsPerBatch.value,
        delayBetweenBatches: delayBetweenBatches.value,
        retryOn429: retryOn429.value,
        maxRetries: maxRetries.value,
        retryDelay: retryDelay.value,
        backoffMultiplier: backoffMultiplier.value
      } : undefined
    };

    const result = await sdk.backend.startCollection(config);
    captures.value = result;
    message.value = `Collected ${result.length} tokens`;

    // Automatically analyze after collection
    const analysisResult = await sdk.backend.analyzeTokens();
    analysis.value = analysisResult;

    // Create position entropy chart if data is available
    await createPositionEntropyChart();
  } catch (error) {
    message.value = "Error during collection";
  }

  isCollecting.value = false;
};

const selectParameter = (param: string) => {
  parameterName.value = param;
  extractableFields.value = [];
  showResponsePreview.value = false;
  message.value = `Selected parameter: ${param}. Click "Start Collection" to begin analysis.`;
};

const copyToClipboard = async (text: string, type: 'headers' | 'body') => {
  try {
    await navigator.clipboard.writeText(text);
    message.value = `${type === 'headers' ? 'Response headers' : 'Response body'} copied to clipboard!`;
  } catch (error) {
    message.value = `Failed to copy ${type}. Please select and copy manually.`;
  }
};

const formatHeaders = (headers?: Record<string, string | string[]>): string => {
  if (!headers) return 'No headers';

  let formatted = '';
  for (const [name, value] of Object.entries(headers)) {
    if (Array.isArray(value)) {
      value.forEach(v => {
        formatted += `${name}: ${v}\n`;
      });
    } else {
      formatted += `${name}: ${value}\n`;
    }
  }
  return formatted || 'No headers';
};

const getFormattedDateTime = () => {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  const hours = String(now.getHours()).padStart(2, '0');
  const minutes = String(now.getMinutes()).padStart(2, '0');
  const seconds = String(now.getSeconds()).padStart(2, '0');
  return `${year}-${month}-${day}_${hours}-${minutes}-${seconds}`;
};

const downloadCSV = async () => {
  try {
    const csv = await sdk.backend.exportCSV();
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `tokens_${getFormattedDateTime()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (error) {
    message.value = "Error exporting CSV";
  }
};

const downloadJSON = async () => {
  try {
    const json = await sdk.backend.exportJSON();
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `analysis_${getFormattedDateTime()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (error) {
    message.value = "Error exporting JSON";
  }
};

const getPlainEnglishVerdict = (analysis: any) => {
  const rating = analysis.security.overallRating;
  const effBits = analysis.entropyAnalysis?.effectiveSecurityBits || 0;
  const dupPercent = analysis.summary.duplicatePercentage;
  const hasSequential = analysis.patterns?.sequential || false;
  const hasTimestamp = analysis.patterns?.timestamp || false;

  if (rating === 'CRITICAL') {
    if (dupPercent > 50) return "Tokens repeat constantly - same values reused across multiple requests";
    if (dupPercent > 20) return "Tokens show high duplication rate - many values appear multiple times";
    if (effBits < 32) return "Tokens are easily guessable - an attacker needs only thousands of attempts to find valid tokens";
    if (hasSequential) return "Tokens follow predictable patterns - they increment or follow a sequence";
    if (hasTimestamp) return "Tokens are based on timestamps - attackers can predict values based on time";
    return "Tokens have critical cryptographic weaknesses that make them unsafe for production use";
  }

  if (rating === 'WARNING') {
    if (dupPercent > 5) return "Some tokens repeat - duplication rate is higher than recommended for secure systems";
    if (effBits < 80) return "Tokens have moderate security - could be vulnerable to dedicated attackers with significant resources";
    if (effBits < 100) return "Tokens meet minimum requirements but fall short of best practices for cryptographic strength";
    return "Tokens show some security concerns - improvements recommended before production deployment";
  }

  if (rating === 'GOOD') {
    if (effBits >= 128 && effBits < 200) return "Tokens are cryptographically secure - meet NIST recommendations for production systems";
    return "Tokens show good randomness properties - suitable for most security applications";
  }

  if (rating === 'EXCELLENT') {
    return "Tokens demonstrate excellent cryptographic quality - exceed security requirements with strong randomness";
  }

  return "Unable to assess token security";
};

const getKeyProblems = (analysis: any) => {
  const problems: string[] = [];
  const dupPercent = analysis.summary.duplicatePercentage;
  const effBits = analysis.entropyAnalysis?.effectiveSecurityBits || 0;
  const minEntropy = analysis.entropyAnalysis?.minEntropyPerBit || 0;
  const chiSquared = analysis.entropyAnalysis?.chiSquaredTest?.pValue;
  const serialCorr = analysis.entropyAnalysis?.serialCorrelation;
  const lzRatio = analysis.entropyAnalysis?.lzCompressionRatio || 0;

  if (dupPercent > 10) problems.push(`${dupPercent.toFixed(1)}% of tokens are duplicates (threshold: 5%)`);
  if (dupPercent > 0 && dupPercent <= 10 && dupPercent > 5) problems.push(`${dupPercent.toFixed(1)}% duplication rate - slightly above recommended 5% threshold`);

  if (effBits < 64) problems.push(`Only ${effBits.toFixed(1)} effective security bits (minimum: 128 bits required)`);
  else if (effBits < 128) problems.push(`${effBits.toFixed(1)} effective security bits - below NIST recommended 128 bits`);

  if (minEntropy < 0.9) problems.push(`Low min-entropy per bit (${minEntropy.toFixed(3)}) - some characters or positions are biased`);

  if (chiSquared !== undefined && chiSquared < 0.05) problems.push(`Chi-squared test failed (p=${chiSquared.toFixed(4)}) - bits are not uniformly distributed`);

  if (serialCorr !== undefined && Math.abs(serialCorr) > 0.1) problems.push(`High serial correlation (${serialCorr.toFixed(3)}) - consecutive bits are not independent`);

  if (lzRatio > 1.05) problems.push(`High compression ratio (${lzRatio.toFixed(2)}) - tokens contain detectable patterns or structure`);

  if (analysis.patterns?.sequential) problems.push("Tokens follow sequential/incrementing patterns");
  if (analysis.patterns?.timestamp) problems.push("Tokens appear to be timestamp-based");
  if (analysis.patterns?.commonPrefix) problems.push(`Common prefix detected: "${analysis.patterns.commonPrefix}"`);
  if (analysis.patterns?.commonSuffix) problems.push(`Common suffix detected: "${analysis.patterns.commonSuffix}"`);

  return problems;
};

const getSecurityImpact = (analysis: any) => {
  const impacts: string[] = [];
  const rating = analysis.security.overallRating;
  const effBits = analysis.entropyAnalysis?.effectiveSecurityBits || 0;
  const dupPercent = analysis.summary.duplicatePercentage;

  if (rating === 'CRITICAL') {
    if (dupPercent > 30) impacts.push("Attacker can reuse captured tokens to gain unauthorized access");
    if (effBits < 32) impacts.push("Brute force attack feasible within hours using standard hardware");
    if (effBits < 64) impacts.push("Session hijacking and token forgery are practical attack vectors");
    if (analysis.patterns?.sequential) impacts.push("Attacker can predict next valid token by observing the pattern");
    if (analysis.patterns?.timestamp) impacts.push("Token values can be guessed by knowing approximate request time");
    impacts.push("Tokens should NOT be used for authentication, session management, or CSRF protection");
  }

  if (rating === 'WARNING') {
    if (dupPercent > 5) impacts.push("Token reuse may allow replay attacks in some scenarios");
    if (effBits < 100) impacts.push("Vulnerable to targeted attacks by well-resourced adversaries");
    impacts.push("May not meet compliance requirements for financial or healthcare applications");
    impacts.push("Consider upgrading token generation for high-security environments");
  }

  if (rating === 'GOOD') {
    impacts.push("Suitable for standard web application security (sessions, CSRF tokens)");
    impacts.push("Meets NIST SP 800-90B recommendations for cryptographic randomness");
    if (effBits < 200) impacts.push("For highly sensitive systems, consider increasing entropy to 256+ bits");
  }

  if (rating === 'EXCELLENT') {
    impacts.push("Exceeds security requirements for all common use cases");
    impacts.push("Resistant to brute force, prediction, and cryptanalytic attacks");
    impacts.push("Suitable for cryptographic keys, API tokens, and high-security applications");
  }

  return impacts;
};

const getRecommendations = (analysis: any) => {
  const recommendations: string[] = [];
  const rating = analysis.security.overallRating;
  const effBits = analysis.entropyAnalysis?.effectiveSecurityBits || 0;
  const dupPercent = analysis.summary.duplicatePercentage;
  const minEntropy = analysis.entropyAnalysis?.minEntropyPerBit || 0;

  if (rating === 'CRITICAL' || rating === 'WARNING') {
    if (dupPercent > 5) {
      recommendations.push("Use cryptographically secure random number generator (CSPRNG) like /dev/urandom, secrets module (Python), or crypto.getRandomValues (JavaScript)");
      recommendations.push("Ensure each token is generated from a fresh random source, not cached or reused");
    }

    if (effBits < 128) {
      recommendations.push("Increase token length to at least 128 bits (16 bytes) for cryptographic security");
      recommendations.push("Use base64 or hexadecimal encoding of random bytes instead of custom character sets");
    }

    if (minEntropy < 0.9) {
      recommendations.push("Verify all character positions use full character set uniformly - no biased positions");
      recommendations.push("Avoid mixing predictable data (timestamps, counters) with random data");
    }

    if (analysis.patterns?.sequential) {
      recommendations.push("Remove sequential/incrementing components - use purely random generation");
    }

    if (analysis.patterns?.timestamp) {
      recommendations.push("Do not base tokens on timestamps - this makes them predictable");
      recommendations.push("If time-based expiry is needed, use separate signed metadata, not embedded in token");
    }

    recommendations.push("Consider using established libraries: secrets (Python), crypto.randomBytes (Node.js), SecureRandom (Java)");
    recommendations.push("After fixing, retest with 10,000+ samples to verify improvements");
  }

  if (rating === 'GOOD') {
    recommendations.push("Current implementation meets security standards for production use");
    if (effBits < 200) recommendations.push("For maximum security, consider increasing to 256 bits");
    recommendations.push("Implement token rotation and expiration policies");
    recommendations.push("Monitor for anomalies in production usage");
  }

  if (rating === 'EXCELLENT') {
    recommendations.push("Token generation meets cryptographic best practices");
    recommendations.push("Maintain current implementation and security controls");
    recommendations.push("Ensure proper token storage (hashed, encrypted at rest)");
    recommendations.push("Implement rate limiting and anomaly detection");
  }

  return recommendations;
};

const getSeverityColor = (rating: string) => {
  switch (rating) {
    case 'CRITICAL': return 'danger';
    case 'WARNING': return 'warn';
    case 'GOOD': return 'info';
    case 'EXCELLENT': return 'success';
    default: return 'info';
  }
};

const createPositionEntropyChart = async () => {
  await nextTick();

  if (!positionEntropyCanvas.value || !analysis.value?.entropyAnalysis?.perPositionData) {
    return;
  }

  // Destroy existing chart if it exists
  if (positionEntropyChart) {
    positionEntropyChart.destroy();
    positionEntropyChart = null;
  }

  const posData = analysis.value.entropyAnalysis.perPositionData;
  if (posData.length === 0) return;

  const ctx = positionEntropyCanvas.value.getContext('2d');
  if (!ctx) return;

  // Calculate ideal entropy (max possible) - log2 of character set size
  // For most tokens, this would be around 6-7 bits (64-128 charset)
  const idealEntropy = 6; // Assume base64-like charset for comparison

  positionEntropyChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: posData.map(d => `Pos ${d.position}`),
      datasets: [{
        label: 'Entropy (bits)',
        data: posData.map(d => d.entropy),
        backgroundColor: posData.map(d => {
          // Color based on entropy quality
          const ratio = d.entropy / idealEntropy;
          if (ratio < 0.5) return 'rgba(239, 68, 68, 0.8)'; // Red - critical
          if (ratio < 0.75) return 'rgba(245, 158, 11, 0.8)'; // Yellow - warning
          return 'rgba(34, 197, 94, 0.8)'; // Green - good
        }),
        borderColor: posData.map(d => {
          const ratio = d.entropy / idealEntropy;
          if (ratio < 0.5) return 'rgba(239, 68, 68, 1)';
          if (ratio < 0.75) return 'rgba(245, 158, 11, 1)';
          return 'rgba(34, 197, 94, 1)';
        }),
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        title: {
          display: true,
          text: 'Entropy per Character Position (Lower = More Predictable)',
          color: '#9ca3af',
          font: { size: 14, weight: 'bold' }
        },
        tooltip: {
          callbacks: {
            label: (context) => {
              const idx = context.dataIndex;
              const d = posData[idx];
              return [
                `Entropy: ${d.entropy.toFixed(2)} bits`,
                `Most common: '${d.mostCommonChar}'`,
                `Frequency: ${(d.frequency * 100).toFixed(1)}%`
              ];
            }
          }
        },
        legend: {
          display: false
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          max: idealEntropy,
          title: {
            display: true,
            text: 'Entropy (bits)',
            color: '#9ca3af'
          },
          ticks: {
            color: '#9ca3af'
          },
          grid: {
            color: 'rgba(156, 163, 175, 0.1)'
          }
        },
        x: {
          title: {
            display: true,
            text: 'Token Position',
            color: '#9ca3af'
          },
          ticks: {
            color: '#9ca3af',
            maxRotation: 45,
            minRotation: 0
          },
          grid: {
            color: 'rgba(156, 163, 175, 0.1)'
          }
        }
      }
    }
  });
};
</script>

<template>
  <div class="h-full overflow-y-auto">
    <HelpDocs v-if="showHelp" @close="showHelp = false" />

    <div v-else class="p-6 pb-24">
      <div class="flex justify-between items-center mb-4">
        <h1 class="text-2xl font-bold">Random Sequencer</h1>
        <Button
          label="Help & Documentation"
          icon="pi pi-question-circle"
          @click="showHelp = true"
          class="p-button-outlined p-button-info"
        />
      </div>
    
    <Card class="mb-4">
      <template #title>Token Collection</template>
      <template #content>
        <div class="space-y-4">
          <div>
            <label class="block mb-2">HTTP Request</label>
            <Textarea
              v-model="httpRequest"
              placeholder="POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=test&password=pass"
              rows="8"
              class="w-full font-mono text-sm"
              :disabled="isCollecting"
            />
            <small class="text-gray-500">Paste the HTTP request that returns tokens in its response.</small>
          </div>

          <div class="flex gap-4 items-end">
            <div class="flex-1">
              <label class="block mb-2">Token Parameter Name</label>
              <InputText
                v-model="parameterName"
                placeholder="e.g., token, csrf_token, sessionId"
                :disabled="isCollecting"
              />
              <small class="text-gray-500">Leave empty and click "Show Fields" to see available parameters</small>
            </div>
            <div>
              <label class="block mb-2">Request Count</label>
              <InputNumber
                v-model="tokenCount"
                :min="5"
                :max="50000"
                :disabled="isCollecting"
              />
            </div>
            <Button
              :label="parameterName.trim() ? 'Start Collection' : 'Show Fields'"
              @click="startCollection"
              :disabled="isCollecting || !httpRequest.trim()"
              :severity="parameterName.trim() ? 'success' : 'info'"
            />
          </div>

          <!-- Rate Limiting Section -->
          <div class="border-t pt-4 mt-4">
            <div class="flex items-center gap-2 mb-3">
              <Checkbox
                v-model="rateLimitEnabled"
                :binary="true"
                inputId="rateLimit"
                :disabled="isCollecting"
              />
              <label for="rateLimit" class="font-semibold cursor-pointer">
                Enable Rate Limiting
              </label>
              <span class="text-xs text-gray-500 ml-2">
                (Prevent overwhelming the server with requests)
              </span>
            </div>

            <!-- Rate Limiting Options (shown when enabled) -->
            <div v-if="rateLimitEnabled" class="ml-6 space-y-3 p-4 rounded border border-[#616161]" style="background-color: #30333b;">
              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="block mb-2 text-sm">Requests per Batch</label>
                  <InputNumber
                    v-model="requestsPerBatch"
                    :min="1"
                    :max="1000"
                    :disabled="isCollecting"
                    class="w-full"
                  />
                  <small class="text-gray-500">Number of requests before pausing</small>
                </div>
                <div>
                  <label class="block mb-2 text-sm">Delay Between Batches (ms)</label>
                  <InputNumber
                    v-model="delayBetweenBatches"
                    :min="0"
                    :max="60000"
                    :step="100"
                    :disabled="isCollecting"
                    class="w-full"
                  />
                  <small class="text-gray-500">Wait time after each batch</small>
                </div>
              </div>

              <div class="border-t pt-3 mt-3">
                <div class="flex items-center gap-2 mb-3">
                  <Checkbox
                    v-model="retryOn429"
                    :binary="true"
                    inputId="retry429"
                    :disabled="isCollecting"
                  />
                  <label for="retry429" class="font-medium cursor-pointer text-sm">
                    Auto-retry on Rate Limit (HTTP 429)
                  </label>
                </div>

                <div v-if="retryOn429" class="ml-6 grid grid-cols-3 gap-4">
                  <div>
                    <label class="block mb-2 text-sm">Max Retries</label>
                    <InputNumber
                      v-model="maxRetries"
                      :min="1"
                      :max="10"
                      :disabled="isCollecting"
                      class="w-full"
                    />
                    <small class="text-gray-500">Retry attempts</small>
                  </div>
                  <div>
                    <label class="block mb-2 text-sm">Retry Delay (ms)</label>
                    <InputNumber
                      v-model="retryDelay"
                      :min="100"
                      :max="30000"
                      :step="100"
                      :disabled="isCollecting"
                      class="w-full"
                    />
                    <small class="text-gray-500">Initial retry wait</small>
                  </div>
                  <div>
                    <label class="block mb-2 text-sm">Backoff Multiplier</label>
                    <InputNumber
                      v-model="backoffMultiplier"
                      :min="1"
                      :max="5"
                      :step="0.5"
                      :disabled="isCollecting"
                      class="w-full"
                    />
                    <small class="text-gray-500">Delay growth factor</small>
                  </div>
                </div>
              </div>

              <div class="p-3 mt-3 rounded border border-[#616161]" style="background-color: #30333b;">
                <p class="text-sm">
                  <strong>Example:</strong> With {{ requestsPerBatch }} requests/batch and {{ delayBetweenBatches }}ms delay,
                  {{ tokenCount }} total requests will take approximately
                  {{ Math.ceil(tokenCount / requestsPerBatch) * (delayBetweenBatches / 1000) + (tokenCount * 0.1) }} seconds.
                </p>
              </div>
            </div>
          </div>
        </div>
      </template>
    </Card>

    <!-- Status Message -->
    <Message
      v-if="message && message !== 'Ready'"
      :severity="message.startsWith('Error') || message.startsWith('Request failed') ? 'error' : message.startsWith('Selected') || message.startsWith('Found') || message.startsWith('Response loaded') ? 'success' : 'info'"
      :closable="false"
      class="mb-4"
    >
      {{ message }}
    </Message>

    <Card v-if="captures.length > 0" class="mb-4">
      <template #title>
        <div class="flex justify-between items-center">
          <span>Collected Responses ({{ captures.length }})</span>
          <Button
            label="View All Responses"
            @click="showTokensDialog = true"
            size="small"
            severity="info"
          />
        </div>
      </template>
      <template #content>
        <div class="text-sm text-gray-600 dark:text-gray-400">
          <span v-if="captures.length === 1 && (captures[0]?.token.startsWith('Request failed') || captures[0]?.token.startsWith('Failed to send'))">
            Request failed. Click "View All Responses" to see error details.
          </span>
          <span v-else>
            Successfully collected {{ captures.length }} response(s). Click "View All Responses" to inspect details.
          </span>
        </div>
      </template>
    </Card>

    <!-- Responses Dialog -->
    <Dialog
      v-model:visible="showTokensDialog"
      header="Collected Responses"
      :style="{ width: '80vw' }"
      :modal="true"
      :dismissableMask="true"
      :pt="{
        content: {
          style: { 'background-color': '#30333b' }
        }
      }"
    >
      <div class="max-h-[60vh] overflow-y-auto">
        <div class="space-y-2">
          <div
            v-for="(capture, index) in captures"
            :key="index"
            class="p-3 border border-[#616161] rounded mb-2 cursor-pointer hover:opacity-80"
            style="background-color: #25272d;"
            @click="selectedCapture = capture; showTokenDetailsDialog = true"
          >
            <div class="flex justify-between items-center">
              <div>
                <strong>{{ index + 1 }}.</strong>
                <span class="font-mono">{{ capture.token.length > 50 ? capture.token.substring(0, 50) + '...' : capture.token }}</span>
              </div>
              <div class="text-sm text-gray-500">
                {{ capture.extractedFrom }}
              </div>
            </div>
          </div>
        </div>
      </div>
    </Dialog>

    <!-- Request Response Dialog -->
    <Dialog
      v-model:visible="showTokenDetailsDialog"
      header="Request Response"
      :style="{ width: '70vw' }"
      :modal="true"
      :dismissableMask="true"
      :pt="{
        content: {
          style: { 'user-select': 'text', '-webkit-user-select': 'text', 'background-color': '#30333b' }
        }
      }"
    >
      <div v-if="selectedCapture" class="space-y-4">
        <div>
          <h4 class="font-semibold mb-2">Extracted Token:</h4>
          <div class="font-mono p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-700 rounded break-all">
            {{ selectedCapture.token }}
          </div>
          <small class="text-gray-500">Source: {{ selectedCapture.extractedFrom }}</small>
        </div>

        <div>
          <h4 class="font-semibold mb-2">Request Sent:</h4>
          <pre class="font-mono text-sm p-3 border border-[#616161] rounded overflow-x-auto" style="background-color: #25272d;" @contextmenu.stop @copy.stop>{{ selectedCapture.requestSent }}</pre>
        </div>

        <div>
          <h4 class="font-semibold mb-2">Response Received:</h4>
          <pre class="font-mono text-sm p-3 border border-[#616161] rounded overflow-x-auto max-h-64 overflow-y-auto" style="background-color: #25272d;" @contextmenu.stop @copy.stop>{{ selectedCapture.responseReceived }}</pre>
        </div>
      </div>
    </Dialog>

    <!-- Response Preview Dialog -->
    <Dialog
      v-model:visible="showResponsePreview"
      header="Response Viewer - Select Parameter Name"
      :style="{ width: '90vw', maxWidth: '1400px' }"
      :modal="true"
      :dismissableMask="true"
      :pt="{
        content: {
          style: { 'user-select': 'text', '-webkit-user-select': 'text', 'background-color': '#30333b' }
        }
      }"
    >
      <div class="space-y-4">
        <div class="p-3 rounded border border-[#616161]" style="background-color: #25272d;">
          <p class="text-sm mb-2">
            <strong>Instructions:</strong>
          </p>
          <ol class="text-sm list-decimal list-inside space-y-1">
            <li>Find the parameter name in the response below (e.g., in Set-Cookie headers or JSON body)</li>
            <li>Use the quick select buttons below, or select text manually and copy it (Ctrl+C)</li>
            <li>You can also use the "Copy" button to copy entire headers or body sections</li>
            <li>Paste the parameter name in the "Token Parameter Name" field</li>
          </ol>
        </div>

        <div v-if="extractableFields.length > 0" class="p-3 rounded border border-[#616161]" style="background-color: #25272d;">
          <p class="text-sm mb-2">
            <strong>Quick Select:</strong> Found {{ extractableFields.length }} potential parameters. Click to use:
          </p>
          <div class="flex flex-wrap gap-2">
            <Button
              v-for="(field, index) in extractableFields"
              :key="index"
              @click="selectParameter(field.name)"
              :label="field.name"
              size="small"
              severity="success"
              :pt="{ label: { style: 'font-weight: bold' } }"
              :title="`${field.source}: ${field.value}`"
            />
          </div>
        </div>

        <div class="grid grid-cols-2 gap-4">
          <!-- Response Headers -->
          <div>
            <div class="flex items-center justify-between mb-2 p-3 rounded border border-[#616161]" style="background-color: #30333b;">
              <h3 class="font-bold flex items-center gap-2">
                <span>Response Headers</span>
              </h3>
              <Button
                icon="pi pi-copy"
                label="Copy All"
                size="small"
                severity="success"
                @click="copyToClipboard(formatHeaders(previewResponse?.headers), 'headers')"
                :pt="{ label: { style: 'font-weight: bold' } }"
              />
            </div>
            <pre class="response-viewer font-mono text-sm p-4 rounded overflow-auto max-h-[50vh] border border-[#616161]" style="background-color: #25272d;" @contextmenu.stop @copy.stop>{{ formatHeaders(previewResponse?.headers) }}</pre>
          </div>

          <!-- Response Body -->
          <div>
            <div class="flex items-center justify-between mb-2 p-3 rounded border border-[#616161]" style="background-color: #30333b;">
              <h3 class="font-bold flex items-center gap-2">
                <span>Response Body</span>
              </h3>
              <Button
                icon="pi pi-copy"
                label="Copy All"
                size="small"
                severity="success"
                @click="copyToClipboard(previewResponse?.body || '', 'body')"
                :pt="{ label: { style: 'font-weight: bold' } }"
              />
            </div>
            <pre class="response-viewer font-mono text-sm p-4 rounded overflow-auto max-h-[50vh] border border-[#616161]" style="background-color: #25272d;" @contextmenu.stop @copy.stop>{{ previewResponse?.body || 'No body' }}</pre>
          </div>
        </div>

        <div class="flex justify-between items-center p-3 rounded border border-[#616161]" style="background-color: #25272d;">
          <span class="text-sm">
            <strong>Tip:</strong> Look for parameter names in Set-Cookie headers, JSON keys, or form fields
          </span>
          <Button
            label="Close"
            @click="showResponsePreview = false"
            severity="danger"
            size="small"
            :pt="{ label: { style: 'font-weight: bold' } }"
          />
        </div>
      </div>
    </Dialog>

    <!-- Technical Details Dialog -->
    <Dialog
      v-model:visible="showTechnicalDetailsDialog"
      header="Technical Analysis Details - NIST 800-90B Metrics"
      :style="{ width: '90vw', maxWidth: '1200px' }"
      :modal="true"
      :dismissableMask="true"
      :pt="{
        content: {
          style: { 'background-color': '#30333b' }
        }
      }"
    >
      <div v-if="analysis" class="space-y-4">
        <!-- NIST 800-90B Entropy Analysis -->
        <div v-if="analysis.entropyAnalysis">
          <h3 class="font-bold text-lg mb-3">NIST 800-90B Entropy Analysis</h3>

          <!-- Entropy Metrics Grid -->
          <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
            <div class="p-3 rounded border border-[#616161]" style="background-color: #25272d;">
              <div class="text-xs text-gray-500 uppercase mb-1">Effective Security Bits</div>
              <div class="text-2xl font-bold" :class="
                analysis.entropyAnalysis.effectiveSecurityBits < 64 ? 'text-red-600 dark:text-red-400' :
                analysis.entropyAnalysis.effectiveSecurityBits < 128 ? 'text-yellow-600 dark:text-yellow-400' :
                'text-green-600 dark:text-green-400'
              ">
                {{ analysis.entropyAnalysis.effectiveSecurityBits.toFixed(1) }}
              </div>
              <div class="text-xs text-gray-500 mt-1">Primary security metric</div>
            </div>

            <div class="p-3 rounded border border-[#616161]" style="background-color: #25272d;">
              <div class="text-xs text-gray-500 uppercase mb-1">Shannon Entropy/bit</div>
              <div class="text-2xl font-bold">{{ analysis.entropyAnalysis.shannonEntropyPerBit.toFixed(4) }}</div>
              <div class="text-xs text-gray-500 mt-1">Average randomness</div>
            </div>

            <div class="p-3 rounded border border-[#616161]" style="background-color: #25272d;">
              <div class="text-xs text-gray-500 uppercase mb-1">Min-Entropy/bit</div>
              <div class="text-2xl font-bold" :class="
                analysis.entropyAnalysis.minEntropyPerBit < 0.8 ? 'text-red-600 dark:text-red-400' :
                analysis.entropyAnalysis.minEntropyPerBit < 0.9 ? 'text-yellow-600 dark:text-yellow-400' :
                'text-green-600 dark:text-green-400'
              ">
                {{ analysis.entropyAnalysis.minEntropyPerBit.toFixed(4) }}
              </div>
              <div class="text-xs text-gray-500 mt-1">Worst-case guessability</div>
            </div>

            <div class="p-3 rounded border border-[#616161]" style="background-color: #25272d;">
              <div class="text-xs text-gray-500 uppercase mb-1">Per-Position Min-Entropy</div>
              <div class="text-2xl font-bold">{{ analysis.entropyAnalysis.perPositionMinEntropy.toFixed(4) }}</div>
              <div class="text-xs text-gray-500 mt-1">Position-by-position</div>
            </div>

            <div class="p-3 rounded border border-[#616161]" style="background-color: #25272d;">
              <div class="text-xs text-gray-500 uppercase mb-1">LZ Compression Ratio</div>
              <div class="text-2xl font-bold" :class="
                analysis.entropyAnalysis.lzCompressionRatio > 1.2 ? 'text-red-600 dark:text-red-400' :
                analysis.entropyAnalysis.lzCompressionRatio > 1.05 ? 'text-yellow-600 dark:text-yellow-400' :
                'text-green-600 dark:text-green-400'
              ">
                {{ analysis.entropyAnalysis.lzCompressionRatio.toFixed(3) }}
              </div>
              <div class="text-xs text-gray-500 mt-1">Structure detection</div>
            </div>
          </div>

          <!-- Statistical Tests -->
          <div class="mt-4">
            <h4 class="font-semibold mb-2">Statistical Randomness Tests</h4>
            <div class="space-y-2">
              <div class="flex justify-between items-center p-2 rounded border border-[#616161]" style="background-color: #25272d;">
                <span>Chi-Squared Test (uniformity)</span>
                <span class="font-mono">
                  p = {{ analysis.entropyAnalysis.chiSquaredPValue.toFixed(4) }}
                  <span class="ml-2" :class="
                    analysis.entropyAnalysis.chiSquaredPValue < 0.01 ? 'text-red-600 dark:text-red-400' :
                    analysis.entropyAnalysis.chiSquaredPValue < 0.05 ? 'text-yellow-600 dark:text-yellow-400' :
                    'text-green-600 dark:text-green-400'
                  ">
                    {{ analysis.entropyAnalysis.chiSquaredPValue >= 0.05 ? 'PASS' : 'FAIL' }}
                  </span>
                </span>
              </div>

              <div class="flex justify-between items-center p-2 rounded border border-[#616161]" style="background-color: #25272d;">
                <span>Serial Correlation (independence)</span>
                <span class="font-mono">
                  {{ analysis.entropyAnalysis.serialCorrelation.toFixed(4) }}
                  <span class="ml-2" :class="
                    Math.abs(analysis.entropyAnalysis.serialCorrelation) > 0.3 ? 'text-red-600 dark:text-red-400' :
                    Math.abs(analysis.entropyAnalysis.serialCorrelation) > 0.1 ? 'text-yellow-600 dark:text-yellow-400' :
                    'text-green-600 dark:text-green-400'
                  ">
                    {{ Math.abs(analysis.entropyAnalysis.serialCorrelation) <= 0.1 ? 'PASS' : 'WARN' }}
                  </span>
                </span>
              </div>

              <div class="flex justify-between items-center p-2 rounded border border-[#616161]" style="background-color: #25272d;">
                <span>Runs Test (randomness)</span>
                <span class="font-mono">
                  p = {{ analysis.entropyAnalysis.runsTestPValue.toFixed(4) }}
                  <span class="ml-2" :class="
                    analysis.entropyAnalysis.runsTestPValue < 0.01 ? 'text-red-600 dark:text-red-400' :
                    analysis.entropyAnalysis.runsTestPValue < 0.05 ? 'text-yellow-600 dark:text-yellow-400' :
                    'text-green-600 dark:text-green-400'
                  ">
                    {{ analysis.entropyAnalysis.runsTestPValue >= 0.05 ? 'PASS' : 'FAIL' }}
                  </span>
                </span>
              </div>
            </div>
          </div>

          <!-- Collision Analysis -->
          <div v-if="analysis.collisionAnalysis" class="mt-4">
            <h4 class="font-semibold mb-2">Collision Analysis</h4>
            <div class="grid grid-cols-3 gap-2">
              <div class="p-2 text-center rounded border border-[#616161]" style="background-color: #25272d;">
                <div class="text-sm text-gray-500">Exact Duplicates</div>
                <div class="text-xl font-bold" :class="analysis.collisionAnalysis.exactDuplicates > 0 ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'">
                  {{ analysis.collisionAnalysis.exactDuplicates }}
                </div>
              </div>
              <div class="p-2 text-center rounded border border-[#616161]" style="background-color: #25272d;">
                <div class="text-sm text-gray-500">Near-Duplicates (≤2)</div>
                <div class="text-xl font-bold" :class="analysis.collisionAnalysis.nearDuplicates > 0 ? 'text-yellow-600 dark:text-yellow-400' : 'text-green-600 dark:text-green-400'">
                  {{ analysis.collisionAnalysis.nearDuplicates }}
                </div>
              </div>
              <div class="p-2 text-center rounded border border-[#616161]" style="background-color: #25272d;">
                <div class="text-sm text-gray-500">Avg Hamming Distance</div>
                <div class="text-xl font-bold">
                  {{ analysis.collisionAnalysis.averageHammingDistance.toFixed(1) }}
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Pattern Detection -->
        <div v-if="analysis.patterns">
          <h3 class="font-bold text-lg mb-3">Pattern Detection</h3>
          <div class="grid grid-cols-2 gap-3">
            <div class="p-3 rounded border border-[#616161]" style="background-color: #25272d;">
              <div class="text-sm text-gray-500 mb-1">Sequential Patterns</div>
              <div class="font-bold" :class="analysis.patterns.sequential ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'">
                {{ analysis.patterns.sequential ? `DETECTED (${analysis.patterns.sequentialCount} instances)` : 'None' }}
              </div>
            </div>

            <div class="p-3 rounded border border-[#616161]" style="background-color: #25272d;">
              <div class="text-sm text-gray-500 mb-1">Timestamp-Based</div>
              <div class="font-bold" :class="analysis.patterns.hasTimestamps ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'">
                {{ analysis.patterns.hasTimestamps ? 'DETECTED' : 'None' }}
              </div>
            </div>

            <div class="p-3 rounded border border-[#616161]" style="background-color: #25272d;">
              <div class="text-sm text-gray-500 mb-1">Common Prefix</div>
              <div class="font-bold">
                {{ analysis.patterns.commonPrefix || 'None' }}
              </div>
            </div>

            <div class="p-3 rounded border border-[#616161]" style="background-color: #25272d;">
              <div class="text-sm text-gray-500 mb-1">Common Suffix</div>
              <div class="font-bold">
                {{ analysis.patterns.commonSuffix || 'None' }}
              </div>
            </div>

            <div class="p-3 rounded border border-[#616161]" style="background-color: #25272d;">
              <div class="text-sm text-gray-500 mb-1">Predictability Score</div>
              <div class="text-xl font-bold" :class="
                analysis.patterns.predictabilityScore > 50 ? 'text-red-600 dark:text-red-400' :
                analysis.patterns.predictabilityScore > 20 ? 'text-yellow-600 dark:text-yellow-400' :
                'text-green-600 dark:text-green-400'
              ">
                {{ analysis.patterns.predictabilityScore }}/100
              </div>
            </div>
          </div>
        </div>

        <!-- Bit Analysis -->
        <div v-if="analysis.bitAnalysis">
          <h3 class="font-bold text-lg mb-3">Bit-Level Analysis</h3>
          <div class="grid grid-cols-3 gap-3">
            <div class="p-3 rounded border border-[#616161]" style="background-color: #25272d;">
              <div class="text-sm text-gray-500 mb-1">Total Bits</div>
              <div class="text-xl font-bold">{{ analysis.bitAnalysis.totalBits }}</div>
            </div>

            <div class="p-3 rounded border border-[#616161]" style="background-color: #25272d;">
              <div class="text-sm text-gray-500 mb-1">Bit Distribution</div>
              <div class="text-sm font-mono">
                1s: {{ analysis.bitAnalysis.onesCount }} / 0s: {{ analysis.bitAnalysis.zerosCount }}
              </div>
            </div>

            <div class="p-3 rounded border border-[#616161]" style="background-color: #25272d;">
              <div class="text-sm text-gray-500 mb-1">Bit Entropy</div>
              <div class="text-xl font-bold">{{ analysis.bitAnalysis.bitEntropy.toFixed(4) }}</div>
            </div>
          </div>
        </div>

        <!-- Character Analysis -->
        <div v-if="analysis.characterAnalysis">
          <h3 class="font-bold text-lg mb-3">Character Analysis</h3>
          <div class="grid grid-cols-3 gap-3">
            <div class="p-3 rounded border border-[#616161]" style="background-color: #25272d;">
              <div class="text-sm text-gray-500 mb-1">Character Set</div>
              <div class="font-mono text-xs break-all">{{ analysis.characterAnalysis.charset }}</div>
            </div>

            <div class="p-3 rounded border border-[#616161]" style="background-color: #25272d;">
              <div class="text-sm text-gray-500 mb-1">Character Distribution</div>
              <div class="text-xs">
                <div>Alpha: {{ analysis.characterAnalysis.alphabetic }}%</div>
                <div>Numeric: {{ analysis.characterAnalysis.numeric }}%</div>
                <div>Special: {{ analysis.characterAnalysis.special }}%</div>
              </div>
            </div>

            <div class="p-3 rounded border border-[#616161]" style="background-color: #25272d;">
              <div class="text-sm text-gray-500 mb-1">Encoding Detection</div>
              <div class="text-sm">
                <div>Hex: {{ analysis.characterAnalysis.hexadecimal ? 'Yes' : 'No' }}</div>
                <div>Base64: {{ analysis.characterAnalysis.base64 ? 'Yes' : 'No' }}</div>
              </div>
            </div>
          </div>
        </div>

        <!-- Close Button -->
        <div class="flex justify-end mt-4">
          <Button
            label="Close"
            @click="showTechnicalDetailsDialog = false"
            severity="secondary"
            :pt="{ label: { style: 'font-weight: bold' } }"
          />
        </div>
      </div>
    </Dialog>

    <!-- Analysis Results -->
    <Card v-if="analysis" class="mb-4">
      <template #title>
        <div class="flex justify-between items-center">
          <span>Security Analysis Results</span>
          <div class="flex gap-2">
            <Button label="Export CSV" @click="downloadCSV" size="small" severity="success" :disabled="analysis.summary.totalSamples === 0" />
            <Button label="Export JSON" @click="downloadJSON" size="small" severity="success" :disabled="analysis.summary.totalSamples === 0" />
          </div>
        </div>
      </template>
      <template #content>
        <div class="space-y-6">

          <!-- Request Failed Error -->
          <div v-if="analysis.security.issues.length > 0 && analysis.security.issues[0].startsWith('REQUEST_FAILED:')" class="bg-red-50 dark:bg-red-900/20 border-l-4 border-red-500 p-4 rounded">
            <div>
              <h3 class="font-bold text-lg mb-2 text-red-700 dark:text-red-300">Analysis Cannot Be Produced</h3>
              <p class="text-red-800 dark:text-red-200">Requests failed during collection. Check "View All Responses" for detailed error information.</p>
            </div>
          </div>

          <!-- Parameter Not Found Error -->
          <div v-else-if="analysis.security.issues.length > 0 && analysis.security.issues[0].startsWith('PARAMETER_NOT_FOUND:')" class="bg-yellow-50 dark:bg-yellow-900/20 border-l-4 border-yellow-500 p-4 rounded">
            <div>
              <h3 class="font-bold text-lg mb-2 text-yellow-700 dark:text-yellow-300">Analysis Cannot Be Produced</h3>
              <p class="text-yellow-800 dark:text-yellow-200">Parameter not found in responses. Use "Show Fields" to verify the parameter name, or check "View All Responses" to see what was received.</p>
            </div>
          </div>

          <!-- Overall Rating with Plain English Verdict (only show if valid tokens were found) -->
          <div v-else-if="analysis.summary.totalSamples > 0" class="p-6 rounded border-l-4" :class="{
            'border-red-500': analysis.security.overallRating === 'CRITICAL',
            'border-yellow-500': analysis.security.overallRating === 'WARNING',
            'border-blue-500': analysis.security.overallRating === 'GOOD',
            'border-green-500': analysis.security.overallRating === 'EXCELLENT'
          }" style="background-color: #30333b;">
            <!-- Verdict Header -->
            <div class="text-3xl font-bold mb-2" :class="{
              'text-red-700 dark:text-red-400': analysis.security.overallRating === 'CRITICAL',
              'text-yellow-700 dark:text-yellow-400': analysis.security.overallRating === 'WARNING',
              'text-blue-700 dark:text-blue-400': analysis.security.overallRating === 'GOOD',
              'text-green-700 dark:text-green-400': analysis.security.overallRating === 'EXCELLENT'
            }">
              {{ analysis.security.overallRating }}
            </div>
            <div class="text-lg mb-6" :class="{
              'text-red-600 dark:text-red-300': analysis.security.overallRating === 'CRITICAL',
              'text-yellow-600 dark:text-yellow-300': analysis.security.overallRating === 'WARNING',
              'text-blue-600 dark:text-blue-300': analysis.security.overallRating === 'GOOD',
              'text-green-600 dark:text-green-300': analysis.security.overallRating === 'EXCELLENT'
            }">
              {{ getPlainEnglishVerdict(analysis) }}
            </div>

            <div class="space-y-5">
              <!-- Key Problems -->
              <div v-if="getKeyProblems(analysis).length > 0">
                <h4 class="font-bold text-base mb-3 flex items-center gap-2">
                  <span>📋</span>
                  <span>Key Problems Detected:</span>
                </h4>
                <ul class="list-disc list-inside space-y-2 ml-1">
                  <li v-for="(problem, idx) in getKeyProblems(analysis)" :key="idx" class="text-sm leading-relaxed">
                    {{ problem }}
                  </li>
                </ul>
              </div>

              <!-- Security Impact -->
              <div v-if="getSecurityImpact(analysis).length > 0">
                <h4 class="font-bold text-base mb-3 flex items-center gap-2">
                  <span>⚠️</span>
                  <span>Security Impact:</span>
                </h4>
                <ul class="list-disc list-inside space-y-2 ml-1">
                  <li v-for="(impact, idx) in getSecurityImpact(analysis)" :key="idx" class="text-sm leading-relaxed">
                    {{ impact }}
                  </li>
                </ul>
              </div>

              <!-- Recommendations -->
              <div v-if="getRecommendations(analysis).length > 0">
                <h4 class="font-bold text-base mb-3 flex items-center gap-2">
                  <span>✅</span>
                  <span>How to Fix:</span>
                </h4>
                <ul class="list-disc list-inside space-y-2 ml-1">
                  <li v-for="(rec, idx) in getRecommendations(analysis)" :key="idx" class="text-sm leading-relaxed">
                    {{ rec }}
                  </li>
                </ul>
              </div>
            </div>

            <!-- View Technical Details Button -->
            <div class="mt-6">
              <Button
                label="View Technical Details"
                @click="showTechnicalDetailsDialog = true"
                size="small"
                severity="info"
              />
            </div>
          </div>

          <!-- Character Position Entropy Chart -->
          <div v-if="analysis.summary.totalSamples > 0 && analysis.entropyAnalysis?.perPositionData && analysis.entropyAnalysis.perPositionData.length > 0 && !analysis.security.issues[0]?.startsWith('REQUEST_FAILED:') && !analysis.security.issues[0]?.startsWith('PARAMETER_NOT_FOUND:')" class="p-4 rounded border border-[#616161]" style="background-color: #30333b;">
            <div class="h-64">
              <canvas ref="positionEntropyCanvas"></canvas>
            </div>
            <div class="mt-3 text-sm text-gray-400">
              <p>🔴 Red bars show positions with low entropy (predictable characters). 🟡 Yellow bars indicate moderate entropy. 🟢 Green bars show good randomness.</p>
            </div>
          </div>

          <!-- Summary Statistics (only show if valid tokens were found and no errors) -->
          <div v-if="analysis.summary.totalSamples > 0 && !analysis.security.issues[0]?.startsWith('REQUEST_FAILED:') && !analysis.security.issues[0]?.startsWith('PARAMETER_NOT_FOUND:')">
            <h3 class="font-bold text-lg mb-3">Summary Statistics</h3>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div class="p-4 border border-[#616161] rounded hover:shadow-lg transition-shadow cursor-help" style="background-color: #25272d;"
                   v-tooltip.top="'Total number of token samples collected from responses'">
                <div class="text-xs text-gray-500 uppercase mb-1">Total Samples</div>
                <div class="text-3xl font-bold text-blue-600 dark:text-blue-400">{{ analysis.summary.totalSamples }}</div>
                <div class="text-xs text-gray-500 mt-1">Tokens collected</div>
              </div>
              <div class="p-4 border border-[#616161] rounded hover:shadow-lg transition-shadow cursor-help" style="background-color: #25272d;"
                   v-tooltip.top="'Number of unique token values. All tokens should be unique for good randomness'">
                <div class="text-xs text-gray-500 uppercase mb-1">Unique Values</div>
                <div class="text-3xl font-bold" :class="analysis.summary.uniqueValues === analysis.summary.totalSamples ? 'text-green-600 dark:text-green-400' : 'text-yellow-600 dark:text-yellow-400'">
                  {{ analysis.summary.uniqueValues }}
                </div>
                <div class="text-xs text-gray-500 mt-1">{{ ((analysis.summary.uniqueValues / analysis.summary.totalSamples) * 100).toFixed(1) }}% unique</div>
              </div>
              <div class="p-4 border border-[#616161] rounded hover:shadow-lg transition-shadow cursor-help" style="background-color: #25272d;"
                   v-tooltip.top="'Percentage of tokens that appear more than once. High duplicates indicate weak randomness'">
                <div class="text-xs text-gray-500 uppercase mb-1">Duplicates</div>
                <div class="text-3xl font-bold" :class="analysis.summary.duplicatePercentage > 10 ? 'text-red-600 dark:text-red-400' : analysis.summary.duplicatePercentage > 5 ? 'text-yellow-600 dark:text-yellow-400' : 'text-green-600 dark:text-green-400'">
                  {{ analysis.summary.duplicatePercentage.toFixed(1) }}%
                </div>
                <div class="text-xs text-gray-500 mt-1">{{ analysis.summary.duplicateCount }} repeated</div>
              </div>
              <div class="p-4 border border-[#616161] rounded hover:shadow-lg transition-shadow cursor-help" style="background-color: #25272d;"
                   v-tooltip.top="'Shannon entropy measures randomness (0=not random, 8=perfectly random). Values above 4.5 are good'">
                <div class="text-xs text-gray-500 uppercase mb-1">Entropy Score</div>
                <div class="text-3xl font-bold" :class="analysis.summary.entropy < 3 ? 'text-red-600 dark:text-red-400' : analysis.summary.entropy < 4 ? 'text-yellow-600 dark:text-yellow-400' : 'text-green-600 dark:text-green-400'">
                  {{ analysis.summary.entropy.toFixed(2) }}
                </div>
                <div class="text-xs text-gray-500 mt-1">{{ analysis.summary.entropy < 3 ? 'Very low' : analysis.summary.entropy < 4 ? 'Low' : analysis.summary.entropy < 4.5 ? 'Good' : 'Excellent' }}</div>
              </div>
            </div>
          </div>

          <!-- Security Assessment (skip if error) - HIDDEN: Replaced by plain English verdict -->
          <div v-if="false && analysis.security.issues.length > 0 && !analysis.security.issues[0]?.startsWith('REQUEST_FAILED:') && !analysis.security.issues[0]?.startsWith('PARAMETER_NOT_FOUND:')" class="p-4 rounded border border-[#616161] border-l-4 border-l-red-500" style="background-color: #30333b; display: none;">
            <h3 class="font-bold text-lg mb-3 text-red-700 dark:text-red-400">Critical Security Issues</h3>
            <div class="space-y-2">
              <div v-for="(issue, idx) in analysis.security.issues" :key="idx" class="p-2 rounded" style="background-color: #25272d;">
                <div class="text-red-600 dark:text-red-400 font-medium">{{ issue }}</div>
              </div>
            </div>
            <div class="mt-3 text-sm p-3 rounded border border-[#616161]" style="background-color: rgba(239, 68, 68, 0.1);">
              <strong class="text-red-700 dark:text-red-400">Recommendation:</strong> <span class="text-red-600 dark:text-red-300">These tokens are predictable and should not be used for security-critical operations. Consider using cryptographically secure random generators.</span>
            </div>
          </div>

          <div v-if="false && analysis.security.warnings.length > 0" class="p-4 rounded border border-[#616161] border-l-4 border-l-yellow-500" style="background-color: #30333b; display: none;">
            <h3 class="font-bold text-lg mb-3 text-yellow-700 dark:text-yellow-400">Security Warnings</h3>
            <div class="space-y-2">
              <div v-for="(warning, idx) in analysis.security.warnings" :key="idx" class="p-2 rounded" style="background-color: #25272d;">
                <div class="text-yellow-600 dark:text-yellow-400 font-medium">{{ warning }}</div>
              </div>
            </div>
            <div class="mt-3 text-sm p-3 rounded border border-[#616161]" style="background-color: rgba(245, 158, 11, 0.1);">
              <strong class="text-yellow-700 dark:text-yellow-400">Suggestion:</strong> <span class="text-yellow-600 dark:text-yellow-300">Review the token generation algorithm. Consider increasing randomness sources or using established cryptographic libraries.</span>
            </div>
          </div>

          <div v-if="false && analysis.security.strengths.length > 0" class="p-4 rounded border border-[#616161] border-l-4 border-l-green-500" style="background-color: #30333b; display: none;">
            <h3 class="font-bold text-lg mb-3 text-green-700 dark:text-green-400">Security Strengths</h3>
            <div class="space-y-2">
              <div v-for="(strength, idx) in analysis.security.strengths" :key="idx" class="p-2 rounded" style="background-color: #25272d;">
                <div class="text-green-600 dark:text-green-400 font-medium">{{ strength }}</div>
              </div>
            </div>
          </div>

          <!-- Pattern Analysis (only show if valid tokens were found) - HIDDEN: Now in Technical Details dialog -->
          <div v-if="false && !analysis.security.issues[0]?.startsWith('REQUEST_FAILED:') && !analysis.security.issues[0]?.startsWith('PARAMETER_NOT_FOUND:')" class="p-4 rounded border border-[#616161]" style="background-color: #30333b; display: none;">
            <h3 class="font-bold text-lg mb-3">Pattern Detection</h3>
            <div class="space-y-3">
              <div class="p-3 rounded cursor-help border border-[#616161]" style="background-color: #25272d;"
                   v-tooltip.top="'Detects if tokens are sequential numbers like 1, 2, 3... which are highly predictable'">
                <div class="flex justify-between items-center">
                  <div>
                    <div class="font-semibold">Sequential Pattern</div>
                    <div class="text-xs text-gray-500">Tokens incrementing in predictable order</div>
                  </div>
                  <div class="text-right">
                    <span class="px-3 py-1 rounded text-sm font-bold" :class="analysis.patterns.sequential ? 'bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-400' : 'bg-green-50 text-green-700 dark:bg-green-900/30 dark:text-green-400'">
                      {{ analysis.patterns.sequential ? 'DETECTED' : 'None' }}
                    </span>
                  </div>
                </div>
              </div>

              <div class="p-3 rounded cursor-help border border-[#616161]" style="background-color: #25272d;"
                   v-tooltip.top="'Checks if tokens are Unix timestamps. Timestamps are predictable since they increment with time'">
                <div class="flex justify-between items-center">
                  <div>
                    <div class="font-semibold">Timestamp-based Tokens</div>
                    <div class="text-xs text-gray-500">Unix timestamps used as tokens</div>
                  </div>
                  <div class="text-right">
                    <span class="px-3 py-1 rounded text-sm font-bold" :class="analysis.patterns.hasTimestamps ? 'bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-400' : 'bg-green-50 text-green-700 dark:bg-green-900/30 dark:text-green-400'">
                      {{ analysis.patterns.hasTimestamps ? 'DETECTED' : 'None' }}
                    </span>
                  </div>
                </div>
              </div>

              <div class="p-3 rounded cursor-help border border-[#616161]" style="background-color: #25272d;"
                   v-tooltip.top="'Overall predictability score based on multiple factors. Lower is better. >50 is critical, >20 is concerning'">
                <div class="flex justify-between items-center">
                  <div>
                    <div class="font-semibold">Predictability Score</div>
                    <div class="text-xs text-gray-500">Combined predictability metric (0=random, 100=predictable)</div>
                  </div>
                  <div class="text-right">
                    <div class="text-2xl font-bold" :class="analysis.patterns.predictabilityScore > 50 ? 'text-red-600 dark:text-red-400' : analysis.patterns.predictabilityScore > 20 ? 'text-yellow-600 dark:text-yellow-400' : 'text-green-600 dark:text-green-400'">
                      {{ analysis.patterns.predictabilityScore }}<span class="text-sm">/100</span>
                    </div>
                  </div>
                </div>
                <div class="mt-2">
                  <ProgressBar :value="analysis.patterns.predictabilityScore" :showValue="false" :class="analysis.patterns.predictabilityScore > 50 ? 'text-red-500' : analysis.patterns.predictabilityScore > 20 ? 'text-yellow-500' : 'text-green-500'" />
                </div>
              </div>

              <div v-if="analysis.patterns.commonPrefix || analysis.patterns.commonSuffix" class="p-3 rounded border border-[#616161]" style="background-color: #25272d;">
                <div class="font-semibold mb-2">Common Patterns</div>
                <div v-if="analysis.patterns.commonPrefix" class="text-sm mb-1">
                  <span class="text-gray-500">Prefix:</span>
                  <span class="font-mono ml-2 bg-yellow-50 dark:bg-yellow-900/30 px-2 py-1 rounded">{{ analysis.patterns.commonPrefix }}</span>
                </div>
                <div v-if="analysis.patterns.commonSuffix" class="text-sm">
                  <span class="text-gray-500">Suffix:</span>
                  <span class="font-mono ml-2 bg-yellow-50 dark:bg-yellow-900/30 px-2 py-1 rounded">{{ analysis.patterns.commonSuffix }}</span>
                </div>
              </div>
            </div>
          </div>

          <!-- Character Analysis (only show if valid tokens were found) - HIDDEN: Now in Technical Details dialog -->
          <div v-if="false && !analysis.security.issues[0]?.startsWith('REQUEST_FAILED:') && !analysis.security.issues[0]?.startsWith('PARAMETER_NOT_FOUND:')" style="display: none;">
            <h3 class="font-bold text-lg mb-3">Character Analysis</h3>
            <div class="p-4 rounded border border-[#616161]" style="background-color: #30333b;">
              <div class="space-y-2">
                <div class="flex justify-between p-2 border-b border-[#616161]">
                  <span>Character Set:</span>
                  <span class="font-mono text-sm">{{ analysis.characterAnalysis.charset.substring(0, 50) }}{{ analysis.characterAnalysis.charset.length > 50 ? '...' : '' }}</span>
                </div>
                <div class="flex justify-between p-2 border-b border-[#616161]">
                  <span>Format:</span>
                  <span>
                    {{ analysis.characterAnalysis.hexadecimal ? 'Hexadecimal' : analysis.characterAnalysis.base64 ? 'Base64' : 'Mixed' }}
                  </span>
                </div>
                <div class="p-2">
                  <ProgressBar :value="(analysis.characterAnalysis.alphabetic / (analysis.characterAnalysis.alphabetic + analysis.characterAnalysis.numeric + analysis.characterAnalysis.special)) * 100">
                    Alphabetic: {{ ((analysis.characterAnalysis.alphabetic / (analysis.characterAnalysis.alphabetic + analysis.characterAnalysis.numeric + analysis.characterAnalysis.special)) * 100).toFixed(1) }}%
                  </ProgressBar>
                </div>
              </div>
            </div>
          </div>

          <!-- Bit Analysis (only show if valid tokens were found) - HIDDEN: Now in Technical Details dialog -->
          <div v-if="false && !analysis.security.issues[0]?.startsWith('REQUEST_FAILED:') && !analysis.security.issues[0]?.startsWith('PARAMETER_NOT_FOUND:')" style="display: none;">
            <h3 class="font-bold text-lg mb-3">Bit-Level Analysis</h3>
            <div class="p-4 rounded border border-[#616161]" style="background-color: #30333b;">
              <div class="space-y-2">
                <div class="flex justify-between p-2 border-b border-[#616161]">
                  <span>Total Bits:</span>
                  <span>{{ analysis.bitAnalysis.totalBits }}</span>
                </div>
                <div class="flex justify-between p-2 border-b border-[#616161]">
                  <span>Bit Entropy:</span>
                  <span :class="analysis.bitAnalysis.bitEntropy > 0.99 ? 'text-green-600 font-bold' : analysis.bitAnalysis.bitEntropy < 0.9 ? 'text-yellow-600' : ''">
                    {{ analysis.bitAnalysis.bitEntropy.toFixed(4) }}
                  </span>
                </div>
                <div class="p-2">
                  <div class="text-sm mb-1">Bit Distribution</div>
                  <ProgressBar :value="(analysis.bitAnalysis.onesCount / analysis.bitAnalysis.totalBits) * 100">
                    Ones: {{ ((analysis.bitAnalysis.onesCount / analysis.bitAnalysis.totalBits) * 100).toFixed(1) }}% | Zeros: {{ ((analysis.bitAnalysis.zerosCount / analysis.bitAnalysis.totalBits) * 100).toFixed(1) }}%
                  </ProgressBar>
                </div>
              </div>
            </div>
          </div>

          <!-- NIST Entropy Analysis (comprehensive) - HIDDEN: Now in Technical Details dialog -->
          <div v-if="false && analysis.entropyAnalysis && !analysis.security.issues[0]?.startsWith('REQUEST_FAILED:') && !analysis.security.issues[0]?.startsWith('PARAMETER_NOT_FOUND:')" style="display: none;">
            <h3 class="font-bold text-lg mb-3">NIST 800-90B Entropy Analysis</h3>
            <div class="p-4 rounded border border-[#616161]" style="background-color: #30333b;">
              <div class="space-y-3">
                <!-- Effective Security Bits (Most Important) -->
                <div class="p-3 rounded border border-[#616161] border-l-4" :class="
                  analysis.entropyAnalysis.effectiveSecurityBits < 64 ? 'border-l-red-500' :
                  analysis.entropyAnalysis.effectiveSecurityBits < 128 ? 'border-l-yellow-500' :
                  'border-l-green-500'
                " style="background-color: #25272d;">
                  <div class="flex justify-between items-center">
                    <div>
                      <div class="font-bold text-lg" :class="
                        analysis.entropyAnalysis.effectiveSecurityBits < 64 ? 'text-red-700 dark:text-red-400' :
                        analysis.entropyAnalysis.effectiveSecurityBits < 128 ? 'text-yellow-700 dark:text-yellow-400' :
                        'text-green-700 dark:text-green-400'
                      ">
                        Effective Security: {{ analysis.entropyAnalysis.effectiveSecurityBits.toFixed(1) }} bits
                      </div>
                      <div class="text-sm text-gray-600 dark:text-gray-400">
                        Recommended minimum: {{ analysis.security.recommendedMinimum }} bits (NIST)
                      </div>
                    </div>
                    <div class="text-3xl font-bold" :class="
                      analysis.entropyAnalysis.effectiveSecurityBits < 64 ? 'text-red-600 dark:text-red-400' :
                      analysis.entropyAnalysis.effectiveSecurityBits < 128 ? 'text-yellow-600 dark:text-yellow-400' :
                      'text-green-600 dark:text-green-400'
                    ">
                      {{ analysis.entropyAnalysis.effectiveSecurityBits >= 128 ? '✓' : '✗' }}
                    </div>
                  </div>
                </div>

                <!-- Entropy Metrics Grid -->
                <div class="grid grid-cols-2 gap-3">
                  <div class="p-3 rounded border border-[#616161]" style="background-color: #25272d;">
                    <div class="text-xs text-gray-500 uppercase mb-1">Shannon Entropy/bit</div>
                    <div class="text-2xl font-bold">{{ analysis.entropyAnalysis.shannonEntropyPerBit.toFixed(4) }}</div>
                    <div class="text-xs text-gray-500 mt-1">Average uncertainty</div>
                  </div>

                  <div class="p-3 rounded border border-[#616161]" style="background-color: #25272d;">
                    <div class="text-xs text-gray-500 uppercase mb-1">Min-Entropy/bit</div>
                    <div class="text-2xl font-bold" :class="
                      analysis.entropyAnalysis.minEntropyPerBit < 0.5 ? 'text-red-600 dark:text-red-400' :
                      analysis.entropyAnalysis.minEntropyPerBit < 0.8 ? 'text-yellow-600 dark:text-yellow-400' :
                      'text-green-600 dark:text-green-400'
                    ">
                      {{ analysis.entropyAnalysis.minEntropyPerBit.toFixed(4) }}
                    </div>
                    <div class="text-xs text-gray-500 mt-1">Worst-case guessability</div>
                  </div>

                  <div class="p-3 rounded border border-[#616161]" style="background-color: #25272d;">
                    <div class="text-xs text-gray-500 uppercase mb-1">Per-Position Min-Entropy</div>
                    <div class="text-2xl font-bold">{{ analysis.entropyAnalysis.perPositionMinEntropy.toFixed(4) }}</div>
                    <div class="text-xs text-gray-500 mt-1">Position-by-position analysis</div>
                  </div>

                  <div class="p-3 rounded border border-[#616161]" style="background-color: #25272d;">
                    <div class="text-xs text-gray-500 uppercase mb-1">LZ Compression Ratio</div>
                    <div class="text-2xl font-bold" :class="
                      analysis.entropyAnalysis.lzCompressionRatio > 1.2 ? 'text-red-600 dark:text-red-400' :
                      analysis.entropyAnalysis.lzCompressionRatio > 1.05 ? 'text-yellow-600 dark:text-yellow-400' :
                      'text-green-600 dark:text-green-400'
                    ">
                      {{ analysis.entropyAnalysis.lzCompressionRatio.toFixed(3) }}
                    </div>
                    <div class="text-xs text-gray-500 mt-1">Structure detection</div>
                  </div>
                </div>

                <!-- Statistical Tests -->
                <div class="mt-4">
                  <h4 class="font-semibold mb-2">Statistical Randomness Tests</h4>
                  <div class="space-y-2">
                    <div class="flex justify-between items-center p-2 rounded border border-[#616161]" style="background-color: #25272d;">
                      <span>Chi-Squared Test (uniformity)</span>
                      <span class="font-mono">
                        p = {{ analysis.entropyAnalysis.chiSquaredPValue.toFixed(4) }}
                        <span class="ml-2" :class="
                          analysis.entropyAnalysis.chiSquaredPValue < 0.01 ? 'text-red-600 dark:text-red-400' :
                          analysis.entropyAnalysis.chiSquaredPValue < 0.05 ? 'text-yellow-600 dark:text-yellow-400' :
                          'text-green-600 dark:text-green-400'
                        ">
                          {{ analysis.entropyAnalysis.chiSquaredPValue >= 0.05 ? 'PASS' : 'FAIL' }}
                        </span>
                      </span>
                    </div>

                    <div class="flex justify-between items-center p-2 rounded border border-[#616161]" style="background-color: #25272d;">
                      <span>Serial Correlation (independence)</span>
                      <span class="font-mono">
                        {{ analysis.entropyAnalysis.serialCorrelation.toFixed(4) }}
                        <span class="ml-2" :class="
                          Math.abs(analysis.entropyAnalysis.serialCorrelation) > 0.3 ? 'text-red-600 dark:text-red-400' :
                          Math.abs(analysis.entropyAnalysis.serialCorrelation) > 0.1 ? 'text-yellow-600 dark:text-yellow-400' :
                          'text-green-600 dark:text-green-400'
                        ">
                          {{ Math.abs(analysis.entropyAnalysis.serialCorrelation) <= 0.1 ? 'PASS' : 'WARN' }}
                        </span>
                      </span>
                    </div>

                    <div class="flex justify-between items-center p-2 rounded border border-[#616161]" style="background-color: #25272d;">
                      <span>Runs Test (randomness)</span>
                      <span class="font-mono">
                        p = {{ analysis.entropyAnalysis.runsTestPValue.toFixed(4) }}
                        <span class="ml-2" :class="
                          analysis.entropyAnalysis.runsTestPValue < 0.01 ? 'text-red-600 dark:text-red-400' :
                          analysis.entropyAnalysis.runsTestPValue < 0.05 ? 'text-yellow-600 dark:text-yellow-400' :
                          'text-green-600 dark:text-green-400'
                        ">
                          {{ analysis.entropyAnalysis.runsTestPValue >= 0.05 ? 'PASS' : 'FAIL' }}
                        </span>
                      </span>
                    </div>
                  </div>
                </div>

                <!-- Collision Analysis -->
                <div v-if="analysis.collisionAnalysis" class="mt-4">
                  <h4 class="font-semibold mb-2">Collision Analysis</h4>
                  <div class="grid grid-cols-3 gap-2">
                    <div class="p-2 text-center rounded border border-[#616161]" style="background-color: #25272d;">
                      <div class="text-sm text-gray-500">Exact Duplicates</div>
                      <div class="text-xl font-bold" :class="analysis.collisionAnalysis.exactDuplicates > 0 ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'">
                        {{ analysis.collisionAnalysis.exactDuplicates }}
                      </div>
                    </div>
                    <div class="p-2 text-center rounded border border-[#616161]" style="background-color: #25272d;">
                      <div class="text-sm text-gray-500">Near-Duplicates (≤2)</div>
                      <div class="text-xl font-bold" :class="analysis.collisionAnalysis.nearDuplicates > 0 ? 'text-yellow-600 dark:text-yellow-400' : 'text-green-600 dark:text-green-400'">
                        {{ analysis.collisionAnalysis.nearDuplicates }}
                      </div>
                    </div>
                    <div class="p-2 text-center rounded border border-[#616161]" style="background-color: #25272d;">
                      <div class="text-sm text-gray-500">Avg Hamming Distance</div>
                      <div class="text-xl font-bold">
                        {{ analysis.collisionAnalysis.averageHammingDistance.toFixed(1) }}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </template>
    </Card>
    </div>
  </div>
</template>

<style scoped>
/* Centralized box styling - inherits CAIDO's theme naturally */
.standard-box {
  /* Don't set explicit colors - let CAIDO theme handle it */
  font-size: 0.75rem; /* 12px - matches app font size */
}

/* Make all analysis results selectable */
.p-card .font-mono,
.p-card .text-3xl,
.p-card .text-2xl,
.p-card .font-bold,
.p-card span,
.p-card div {
  user-select: text;
  -webkit-user-select: text;
  -moz-user-select: text;
  -ms-user-select: text;
}

/* Make sure buttons and interactive elements are not accidentally selectable */
button,
input,
textarea,
.p-button {
  user-select: none;
  -webkit-user-select: none;
}

/* Response viewer styling */
.response-viewer {
  user-select: text !important;
  -webkit-user-select: text !important;
  -moz-user-select: text !important;
  -ms-user-select: text !important;
  cursor: text !important;
  white-space: pre-wrap;
  word-wrap: break-word;
  line-height: 1.5;
  pointer-events: auto !important;
}

.response-viewer::selection {
  background-color: rgba(59, 130, 246, 0.5) !important;
  color: white !important;
}

.response-viewer::-moz-selection {
  background-color: rgba(59, 130, 246, 0.5) !important;
  color: white !important;
}

/* Force dialog content to be selectable */
:deep(.p-dialog) {
  user-select: text !important;
  -webkit-user-select: text !important;
  -moz-user-select: text !important;
  -ms-user-select: text !important;
}

:deep(.p-dialog-content) {
  user-select: text !important;
  -webkit-user-select: text !important;
  -moz-user-select: text !important;
  -ms-user-select: text !important;
}

:deep(.p-dialog-content pre),
:deep(.p-dialog-content .response-viewer) {
  user-select: text !important;
  -webkit-user-select: text !important;
  -moz-user-select: text !important;
  -ms-user-select: text !important;
  cursor: text !important;
}

:deep(.p-dialog-header) {
  user-select: none !important;
  -webkit-user-select: none !important;
}

/* Ensure all text elements are selectable */
:deep(.p-dialog-content *) {
  user-select: text !important;
  -webkit-user-select: text !important;
}

/* Override PrimeVue button selection blocking */
:deep(.p-dialog-content .p-button) {
  user-select: none !important;
  -webkit-user-select: none !important;
}
</style>