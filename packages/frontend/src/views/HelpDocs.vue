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
            The Random Sequencer plugin helps security researchers analyze the randomness and predictability
            of tokens, session IDs, CSRF tokens, or any parameter returned by a web application. It repeatedly
            sends HTTP requests, captures tokens from responses, and performs statistical analysis to identify
            security weaknesses.
          </p>
        </template>
      </Card>

      <Card class="doc-card">
        <template #title>How It Works</template>
        <template #content>
          <ol>
            <li><strong>Request Repetition:</strong> The plugin sends the same HTTP request multiple times (default: 100)</li>
            <li><strong>Token Extraction:</strong> For each response, it extracts the specified parameter from:
              <ul>
                <li>JSON response bodies</li>
                <li>Set-Cookie headers</li>
                <li>URL-encoded responses</li>
                <li>HTML input fields, meta tags, and data attributes</li>
                <li>JavaScript variable assignments</li>
              </ul>
            </li>
            <li><strong>Statistical Analysis:</strong> All captured tokens are analyzed for randomness and security</li>
          </ol>
        </template>
      </Card>

      <Card class="doc-card">
        <template #title>Understanding the Analysis</template>
        <template #content>
          <h3>Summary Metrics</h3>
          <ul>
            <li><strong>Total Samples:</strong> Number of requests sent and tokens captured</li>
            <li><strong>Unique Values:</strong> Number of distinct tokens received</li>
            <li><strong>Duplicate Count & Percentage:</strong> How many tokens appeared more than once</li>
            <li><strong>Entropy:</strong> Character-level randomness (explained below)</li>
            <li><strong>Length Stats:</strong> Average, minimum, and maximum token lengths</li>
          </ul>

          <h3>What is Entropy?</h3>
          <p>
            <strong>Shannon Entropy</strong> measures how unpredictable the <em>characters</em> are within your tokens.
            It's calculated using the formula:
          </p>
          <div class="formula">
            H = -Σ(p(x) × log₂(p(x)))
          </div>
          <p>where p(x) is the probability of each character appearing.</p>

          <h4>Entropy Scale:</h4>
          <ul>
            <li><strong>&lt; 3.0:</strong> Very Low - Characters are highly predictable (e.g., "111111", "aaaaaa")</li>
            <li><strong>3.0 - 4.0:</strong> Low - Limited character variety</li>
            <li><strong>4.0 - 4.5:</strong> Moderate - Decent character distribution</li>
            <li><strong>&gt; 4.5:</strong> High - Good character randomness (e.g., "a7f3B9E2c1D4")</li>
          </ul>

          <h3>Important: Entropy vs Duplicates</h3>
          <div class="warning-box">
            <p><strong>High entropy does NOT mean the tokens are secure!</strong></p>
            <p>
              You can have high entropy (random-looking characters) but still have high duplicates.
              This happens when:
            </p>
            <ul>
              <li>The server generates random tokens BUT reuses them across requests</li>
              <li>Tokens are cached or session-based</li>
              <li>The 20% unique tokens are very random, but 80% are duplicates</li>
            </ul>
            <p>
              <strong>Example:</strong> If you get tokens like <code>a7f3B9E2c1D4</code> repeated 500 times,
              then <code>x2K9mL3pQ8v1</code> repeated 300 times, then <code>nR4tY7wZ2fG6</code> repeated 200 times (out of 1000 samples):
            </p>
            <ul>
              <li>✅ High entropy (characters are random)</li>
              <li>❌ High duplicates (only 3 unique tokens in 1000 requests)</li>
              <li>❌ CRITICAL security issue (tokens are predictable/reused)</li>
            </ul>
          </div>

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
            <li><strong>Paste HTTP Request:</strong> Copy a raw HTTP request from Caido or Burp Suite</li>
            <li><strong>Specify Parameter Name:</strong> Enter the exact name of the token parameter (e.g., "csrf_token", "sessionId", "token")
              <div class="info-box">
                <strong>Response Viewer Feature:</strong> If you leave the parameter name empty and click "Show Fields",
                the plugin will send a test request and display the response in a Burp Suite-style viewer with two panels:
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
