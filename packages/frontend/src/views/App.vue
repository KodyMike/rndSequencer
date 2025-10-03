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
import { ref, Directive } from "vue";
import { useSDK } from "../plugins/sdk";
import HelpDocs from "./HelpDocs.vue";

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
const previewResponse = ref<{body: string, headers: Record<string, string | string[]>} | null>(null);
const extractableFields = ref<Array<{name: string, value: string, source: string}>>([]);

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

const downloadCSV = async () => {
  try {
    const csv = await sdk.backend.exportCSV();
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `tokens_${Date.now()}.csv`;
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
    a.download = `analysis_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (error) {
    message.value = "Error exporting JSON";
  }
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
            <div v-if="rateLimitEnabled" class="ml-6 space-y-3 p-4 rounded border border-gray-300 dark:border-gray-600">
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

              <div class="p-3 mt-3 rounded border border-gray-300 dark:border-gray-600">
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
    >
      <div class="max-h-[60vh] overflow-y-auto">
        <div class="space-y-2">
          <div
            v-for="(capture, index) in captures"
            :key="index"
            class="p-3 border border-gray-300 rounded mb-2 bg-white dark:bg-gray-800 dark:border-gray-600 dark:text-white cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700"
            @click="selectedCapture = capture; showTokenDetailsDialog = true"
          >
            <div class="flex justify-between items-center">
              <div>
                <strong>{{ index + 1 }}.</strong>
                <span class="font-mono text-sm">{{ capture.token.length > 50 ? capture.token.substring(0, 50) + '...' : capture.token }}</span>
              </div>
              <div class="text-xs text-gray-500">
                {{ capture.extractedFrom }}
              </div>
            </div>
          </div>
        </div>
      </div>
    </Dialog>

    <!-- Token Details Dialog -->
    <Dialog
      v-model:visible="showTokenDetailsDialog"
      header="Token Details"
      :style="{ width: '70vw' }"
      :modal="true"
      :dismissableMask="true"
    >
      <div v-if="selectedCapture" class="space-y-4">
        <div>
          <h4 class="font-semibold mb-2">Extracted Token:</h4>
          <div class="font-mono text-sm p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-700 rounded break-all">
            {{ selectedCapture.token }}
          </div>
          <small class="text-gray-500">Source: {{ selectedCapture.extractedFrom }}</small>
        </div>

        <div>
          <h4 class="font-semibold mb-2">Request Sent:</h4>
          <pre class="font-mono text-xs p-3 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-700 rounded overflow-x-auto">{{ selectedCapture.requestSent }}</pre>
        </div>

        <div>
          <h4 class="font-semibold mb-2">Response Received:</h4>
          <pre class="font-mono text-xs p-3 bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-600 rounded overflow-x-auto max-h-64 overflow-y-auto">{{ selectedCapture.responseReceived }}</pre>
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
    >
      <div class="space-y-4">
        <div class="bg-blue-50 dark:bg-blue-900/20 p-3 rounded border border-blue-200 dark:border-blue-700">
          <p class="text-sm mb-2">
            <strong>Instructions:</strong>
          </p>
          <ol class="text-sm list-decimal list-inside space-y-1">
            <li>Find the parameter name in the response below (e.g., in Set-Cookie headers or JSON body)</li>
            <li>Select/highlight the parameter name with your mouse</li>
            <li>Copy it (Ctrl+C) and paste it in the "Token Parameter Name" field</li>
            <li>Or use the quick select buttons below</li>
          </ol>
        </div>

        <div v-if="extractableFields.length > 0" class="bg-green-50 dark:bg-green-900/20 p-3 rounded border border-green-200 dark:border-green-700">
          <p class="text-sm mb-2">
            <strong>Quick Select:</strong> Found {{ extractableFields.length }} potential parameters. Click to use:
          </p>
          <div class="flex flex-wrap gap-2">
            <button
              v-for="(field, index) in extractableFields"
              :key="index"
              @click="selectParameter(field.name)"
              class="px-3 py-1 bg-green-600 hover:bg-green-700 text-white text-xs rounded cursor-pointer transition-colors"
              :title="`${field.source}: ${field.value}`"
            >
              {{ field.name }}
            </button>
          </div>
        </div>

        <div class="grid grid-cols-2 gap-4">
          <!-- Response Headers -->
          <div>
            <h3 class="font-bold mb-2 flex items-center gap-2">
              <span>Response Headers</span>
              <span class="text-xs text-gray-500">(Select text to copy parameter names)</span>
            </h3>
            <pre class="response-viewer font-mono text-xs p-4 bg-gray-900 text-green-400 rounded overflow-auto max-h-[50vh] border border-gray-700">{{ formatHeaders(previewResponse?.headers) }}</pre>
          </div>

          <!-- Response Body -->
          <div>
            <h3 class="font-bold mb-2 flex items-center gap-2">
              <span>Response Body</span>
              <span class="text-xs text-gray-500">(Select text to copy parameter names)</span>
            </h3>
            <pre class="response-viewer font-mono text-xs p-4 bg-gray-900 text-gray-300 rounded overflow-auto max-h-[50vh] border border-gray-700">{{ previewResponse?.body || 'No body' }}</pre>
          </div>
        </div>

        <div class="flex justify-between items-center p-3 bg-yellow-50 dark:bg-yellow-900/20 rounded border border-yellow-200 dark:border-yellow-700">
          <span class="text-sm">
            <strong>Tip:</strong> Look for parameter names in Set-Cookie headers, JSON keys, or form fields
          </span>
          <Button
            label="Close"
            @click="showResponsePreview = false"
            outlined
            size="small"
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
            <Button label="Export JSON" @click="downloadJSON" size="small" severity="success" />
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

          <!-- Overall Rating (only show if valid tokens were found) -->
          <div v-else-if="analysis.summary.totalSamples > 0" class="border-l-4 p-4 rounded" :class="{
            'border-red-500 bg-red-50 dark:bg-red-900/20': analysis.security.overallRating === 'CRITICAL',
            'border-yellow-500 bg-yellow-50 dark:bg-yellow-900/20': analysis.security.overallRating === 'WARNING',
            'border-blue-500 bg-blue-50 dark:bg-blue-900/20': analysis.security.overallRating === 'GOOD',
            'border-green-500 bg-green-50 dark:bg-green-900/20': analysis.security.overallRating === 'EXCELLENT'
          }">
            <div class="flex items-center justify-between">
              <div>
                <div class="text-2xl font-bold mb-1" :class="{
                  'text-red-700 dark:text-red-400': analysis.security.overallRating === 'CRITICAL',
                  'text-yellow-700 dark:text-yellow-400': analysis.security.overallRating === 'WARNING',
                  'text-blue-700 dark:text-blue-400': analysis.security.overallRating === 'GOOD',
                  'text-green-700 dark:text-green-400': analysis.security.overallRating === 'EXCELLENT'
                }">
                  {{ analysis.security.overallRating }}
                </div>
                <div class="text-sm text-gray-600 dark:text-gray-400">
                  {{
                    analysis.security.overallRating === 'CRITICAL' ? 'Tokens show critical security weaknesses' :
                    analysis.security.overallRating === 'WARNING' ? 'Tokens have some security concerns' :
                    analysis.security.overallRating === 'GOOD' ? 'Tokens show good randomness properties' :
                    'Tokens demonstrate excellent cryptographic strength'
                  }}
                </div>
              </div>
            </div>
          </div>

          <!-- Summary Statistics (only show if valid tokens were found and no errors) -->
          <div v-if="analysis.summary.totalSamples > 0 && !analysis.security.issues[0]?.startsWith('REQUEST_FAILED:') && !analysis.security.issues[0]?.startsWith('PARAMETER_NOT_FOUND:')">
            <h3 class="font-bold text-lg mb-3">Summary Statistics</h3>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div class="p-4 border border-gray-300 dark:border-gray-600 rounded hover:shadow-lg transition-shadow cursor-help"
                   v-tooltip.top="'Total number of token samples collected from responses'">
                <div class="text-xs text-gray-500 uppercase mb-1">Total Samples</div>
                <div class="text-3xl font-bold text-blue-600 dark:text-blue-400">{{ analysis.summary.totalSamples }}</div>
                <div class="text-xs text-gray-500 mt-1">Tokens collected</div>
              </div>
              <div class="p-4 border border-gray-300 dark:border-gray-600 rounded hover:shadow-lg transition-shadow cursor-help"
                   v-tooltip.top="'Number of unique token values. All tokens should be unique for good randomness'">
                <div class="text-xs text-gray-500 uppercase mb-1">Unique Values</div>
                <div class="text-3xl font-bold" :class="analysis.summary.uniqueValues === analysis.summary.totalSamples ? 'text-green-600 dark:text-green-400' : 'text-orange-600 dark:text-orange-400'">
                  {{ analysis.summary.uniqueValues }}
                </div>
                <div class="text-xs text-gray-500 mt-1">{{ ((analysis.summary.uniqueValues / analysis.summary.totalSamples) * 100).toFixed(1) }}% unique</div>
              </div>
              <div class="p-4 border border-gray-300 dark:border-gray-600 rounded hover:shadow-lg transition-shadow cursor-help"
                   v-tooltip.top="'Percentage of tokens that appear more than once. High duplicates indicate weak randomness'">
                <div class="text-xs text-gray-500 uppercase mb-1">Duplicates</div>
                <div class="text-3xl font-bold" :class="analysis.summary.duplicatePercentage > 10 ? 'text-red-600 dark:text-red-400' : analysis.summary.duplicatePercentage > 5 ? 'text-yellow-600 dark:text-yellow-400' : 'text-green-600 dark:text-green-400'">
                  {{ analysis.summary.duplicatePercentage.toFixed(1) }}%
                </div>
                <div class="text-xs text-gray-500 mt-1">{{ analysis.summary.duplicateCount }} repeated</div>
              </div>
              <div class="p-4 border border-gray-300 dark:border-gray-600 rounded hover:shadow-lg transition-shadow cursor-help"
                   v-tooltip.top="'Shannon entropy measures randomness (0=not random, 8=perfectly random). Values above 4.5 are good'">
                <div class="text-xs text-gray-500 uppercase mb-1">Entropy Score</div>
                <div class="text-3xl font-bold" :class="analysis.summary.entropy < 3 ? 'text-red-600 dark:text-red-400' : analysis.summary.entropy < 4 ? 'text-yellow-600 dark:text-yellow-400' : 'text-green-600 dark:text-green-400'">
                  {{ analysis.summary.entropy.toFixed(2) }}
                </div>
                <div class="text-xs text-gray-500 mt-1">{{ analysis.summary.entropy < 3 ? 'Very low' : analysis.summary.entropy < 4 ? 'Low' : analysis.summary.entropy < 4.5 ? 'Good' : 'Excellent' }}</div>
              </div>
            </div>
          </div>

          <!-- Security Assessment (skip if error) -->
          <div v-if="analysis.security.issues.length > 0 && !analysis.security.issues[0]?.startsWith('REQUEST_FAILED:') && !analysis.security.issues[0]?.startsWith('PARAMETER_NOT_FOUND:')" class="bg-red-50 dark:bg-red-900/20 border-l-4 border-red-500 p-4 rounded">
            <h3 class="font-bold text-lg mb-3 text-red-700 dark:text-red-400">Critical Security Issues</h3>
            <div class="space-y-2">
              <div v-for="(issue, idx) in analysis.security.issues" :key="idx" class="p-2 bg-white dark:bg-gray-800 rounded">
                <div class="text-red-600 dark:text-red-400 font-medium">{{ issue }}</div>
              </div>
            </div>
            <div class="mt-3 text-sm text-red-700 dark:text-red-300 bg-red-100 dark:bg-red-900/40 p-2 rounded">
              <strong>Recommendation:</strong> These tokens are predictable and should not be used for security-critical operations. Consider using cryptographically secure random generators.
            </div>
          </div>

          <div v-if="analysis.security.warnings.length > 0" class="bg-yellow-50 dark:bg-yellow-900/20 border-l-4 border-yellow-500 p-4 rounded">
            <h3 class="font-bold text-lg mb-3 text-yellow-700 dark:text-yellow-400">Security Warnings</h3>
            <div class="space-y-2">
              <div v-for="(warning, idx) in analysis.security.warnings" :key="idx" class="p-2 bg-white dark:bg-gray-800 rounded">
                <div class="text-yellow-600 dark:text-yellow-400 font-medium">{{ warning }}</div>
              </div>
            </div>
            <div class="mt-3 text-sm text-yellow-700 dark:text-yellow-300 bg-yellow-100 dark:bg-yellow-900/40 p-2 rounded">
              <strong>Suggestion:</strong> Review the token generation algorithm. Consider increasing randomness sources or using established cryptographic libraries.
            </div>
          </div>

          <div v-if="analysis.security.strengths.length > 0" class="bg-green-50 dark:bg-green-900/20 border-l-4 border-green-500 p-4 rounded">
            <h3 class="font-bold text-lg mb-3 text-green-700 dark:text-green-400">Security Strengths</h3>
            <div class="space-y-2">
              <div v-for="(strength, idx) in analysis.security.strengths" :key="idx" class="p-2 bg-white dark:bg-gray-800 rounded">
                <div class="text-green-600 dark:text-green-400 font-medium">{{ strength }}</div>
              </div>
            </div>
          </div>

          <!-- Pattern Analysis (only show if valid tokens were found) -->
          <div v-if="!analysis.security.issues[0]?.startsWith('REQUEST_FAILED:') && !analysis.security.issues[0]?.startsWith('PARAMETER_NOT_FOUND:')" class="bg-gray-50 dark:bg-gray-800 p-4 rounded">
            <h3 class="font-bold text-lg mb-3">Pattern Detection</h3>
            <div class="space-y-3">
              <div class="bg-white dark:bg-gray-900 p-3 rounded cursor-help"
                   v-tooltip.top="'Detects if tokens are sequential numbers like 1, 2, 3... which are highly predictable'">
                <div class="flex justify-between items-center">
                  <div>
                    <div class="font-semibold">Sequential Pattern</div>
                    <div class="text-xs text-gray-500">Tokens incrementing in predictable order</div>
                  </div>
                  <div class="text-right">
                    <span class="px-3 py-1 rounded text-sm font-bold" :class="analysis.patterns.sequential ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-400' : 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-400'">
                      {{ analysis.patterns.sequential ? 'DETECTED' : 'None' }}
                    </span>
                  </div>
                </div>
              </div>

              <div class="bg-white dark:bg-gray-900 p-3 rounded cursor-help"
                   v-tooltip.top="'Checks if tokens are Unix timestamps. Timestamps are predictable since they increment with time'">
                <div class="flex justify-between items-center">
                  <div>
                    <div class="font-semibold">Timestamp-based Tokens</div>
                    <div class="text-xs text-gray-500">Unix timestamps used as tokens</div>
                  </div>
                  <div class="text-right">
                    <span class="px-3 py-1 rounded text-sm font-bold" :class="analysis.patterns.hasTimestamps ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-400' : 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-400'">
                      {{ analysis.patterns.hasTimestamps ? 'DETECTED' : 'None' }}
                    </span>
                  </div>
                </div>
              </div>

              <div class="bg-white dark:bg-gray-900 p-3 rounded cursor-help"
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

              <div v-if="analysis.patterns.commonPrefix || analysis.patterns.commonSuffix" class="bg-white dark:bg-gray-900 p-3 rounded">
                <div class="font-semibold mb-2">Common Patterns</div>
                <div v-if="analysis.patterns.commonPrefix" class="text-sm mb-1">
                  <span class="text-gray-500">Prefix:</span>
                  <span class="font-mono ml-2 bg-yellow-100 dark:bg-yellow-900/40 px-2 py-1 rounded">{{ analysis.patterns.commonPrefix }}</span>
                </div>
                <div v-if="analysis.patterns.commonSuffix" class="text-sm">
                  <span class="text-gray-500">Suffix:</span>
                  <span class="font-mono ml-2 bg-yellow-100 dark:bg-yellow-900/40 px-2 py-1 rounded">{{ analysis.patterns.commonSuffix }}</span>
                </div>
              </div>
            </div>
          </div>

          <!-- Character Analysis (only show if valid tokens were found) -->
          <div v-if="!analysis.security.issues[0]?.startsWith('REQUEST_FAILED:') && !analysis.security.issues[0]?.startsWith('PARAMETER_NOT_FOUND:')">
            <h3 class="font-bold text-lg mb-3">Character Analysis</h3>
            <div class="space-y-2">
              <div class="flex justify-between p-2 border-b border-gray-300 dark:border-gray-600">
                <span>Character Set:</span>
                <span class="font-mono text-sm">{{ analysis.characterAnalysis.charset.substring(0, 50) }}{{ analysis.characterAnalysis.charset.length > 50 ? '...' : '' }}</span>
              </div>
              <div class="flex justify-between p-2 border-b border-gray-300 dark:border-gray-600">
                <span>Format:</span>
                <span>
                  {{ analysis.characterAnalysis.hexadecimal ? 'Hexadecimal' : analysis.characterAnalysis.base64 ? 'Base64' : 'Mixed' }}
                </span>
              </div>
              <div>
                <ProgressBar :value="(analysis.characterAnalysis.alphabetic / (analysis.characterAnalysis.alphabetic + analysis.characterAnalysis.numeric + analysis.characterAnalysis.special)) * 100">
                  Alphabetic: {{ ((analysis.characterAnalysis.alphabetic / (analysis.characterAnalysis.alphabetic + analysis.characterAnalysis.numeric + analysis.characterAnalysis.special)) * 100).toFixed(1) }}%
                </ProgressBar>
              </div>
            </div>
          </div>

          <!-- Bit Analysis (only show if valid tokens were found) -->
          <div v-if="!analysis.security.issues[0]?.startsWith('REQUEST_FAILED:') && !analysis.security.issues[0]?.startsWith('PARAMETER_NOT_FOUND:')">
            <h3 class="font-bold text-lg mb-3">Bit-Level Analysis</h3>
            <div class="space-y-2">
              <div class="flex justify-between p-2 border-b border-gray-300 dark:border-gray-600">
                <span>Total Bits:</span>
                <span>{{ analysis.bitAnalysis.totalBits }}</span>
              </div>
              <div class="flex justify-between p-2 border-b border-gray-300 dark:border-gray-600">
                <span>Bit Entropy:</span>
                <span :class="analysis.bitAnalysis.bitEntropy > 0.99 ? 'text-green-600 font-bold' : analysis.bitAnalysis.bitEntropy < 0.9 ? 'text-yellow-600' : ''">
                  {{ analysis.bitAnalysis.bitEntropy.toFixed(4) }}
                </span>
              </div>
              <div>
                <div class="text-sm mb-1">Bit Distribution</div>
                <ProgressBar :value="(analysis.bitAnalysis.onesCount / analysis.bitAnalysis.totalBits) * 100">
                  Ones: {{ ((analysis.bitAnalysis.onesCount / analysis.bitAnalysis.totalBits) * 100).toFixed(1) }}% | Zeros: {{ ((analysis.bitAnalysis.zerosCount / analysis.bitAnalysis.totalBits) * 100).toFixed(1) }}%
                </ProgressBar>
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
}

.response-viewer::selection {
  background-color: rgba(59, 130, 246, 0.5) !important;
  color: white !important;
}

/* Force dialog content to be selectable */
:deep(.p-dialog-content) {
  user-select: text !important;
  -webkit-user-select: text !important;
}

:deep(.p-dialog-content pre),
:deep(.p-dialog-content .response-viewer) {
  user-select: text !important;
  -webkit-user-select: text !important;
  cursor: text !important;
}
</style>