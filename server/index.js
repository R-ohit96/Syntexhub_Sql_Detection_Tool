const express = require('express');
const cors = require('cors');
const axios = require('axios');
const cheerio = require('cheerio');
const url = require('url');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 5000;

// SQL Injection Payloads
const payloads = [
    "'",
    "''",
    "`",
    "``",
    ",",
    "\"",
    "\"\"",
    "/",
    "//",
    "\\",
    "\\\\",
    ";",
    "' OR '1'='1",
    "' OR 1=1 --",
    "\" OR 1=1 --",
    "admin' --",
    "admin' #",
    "' UNION SELECT NULL, NULL, NULL --",
    "sleep(5)",
    "' OR SLEEP(5) --"
];

// SQL Error Patterns
const sqlErrors = [
    "SQL syntax",
    "mysql_fetch_array",
    "MySQL Error",
    "ORA-01756",
    "SQLite/JDBCDriver",
    "PostgreSQL query failed",
    "Microsoft OLE DB Provider for SQL Server",
    "Unclosed quotation mark",
    "Incorrect syntax near",
    "Dynamic SQL Error"
];

// Helper for concurrency and rate-limiting
async function runWithConcurrency(tasks, limit, delayMs) {
    const results = [];
    let i = 0;
    while (i < tasks.length) {
        const batch = tasks.slice(i, i + limit);
        const batchResults = await Promise.all(batch.map(async (task) => {
            const res = await task();
            if (delayMs > 0) await new Promise(r => setTimeout(r, delayMs));
            return res;
        }));
        results.push(...batchResults);
        i += limit;
    }
    return results;
}

async function scanURL(targetUrl) {
    const findings = [];
    const logs = [];

    logs.push(`[*] Starting scan on ${targetUrl}`);

    try {
        const response = await axios.get(targetUrl);
        const $ = cheerio.load(response.data);
        const forms = $('form');

        logs.push(`[+] Found ${forms.length} forms`);

        for (let i = 0; i < forms.length; i++) {
            const form = $(forms[i]);
            const action = form.attr('action') || '';
            const method = (form.attr('method') || 'get').toLowerCase();
            const inputs = form.find('input, textarea');
            
            const formUrl = url.resolve(targetUrl, action);
            logs.push(`[!] Testing form ${i + 1} at ${formUrl} (${method})`);

            const formTasks = payloads.map(payload => async () => {
                const formData = {};
                inputs.each((_, input) => {
                    const name = $(input).attr('name');
                    if (name) formData[name] = payload;
                });

                try {
                    let res;
                    const startTime = Date.now();
                    if (method === 'post') {
                        res = await axios.post(formUrl, formData, { timeout: 10000 });
                    } else {
                        res = await axios.get(formUrl, { params: formData, timeout: 10000 });
                    }
                    const endTime = Date.now();
                    const duration = endTime - startTime;

                    const body = res.data;
                    const detectedErrors = sqlErrors.filter(err => body.includes(err));

                    if (detectedErrors.length > 0) {
                        findings.push({ type: 'Error-Based SQLi', payload, url: formUrl, evidence: detectedErrors[0] });
                        logs.push(`[CRITICAL] Possible SQLi detected with payload: ${payload}`);
                    }

                    if (duration > 5000 && (payload.includes('sleep') || payload.includes('SLEEP'))) {
                        findings.push({ type: 'Time-Based SQLi', payload, url: formUrl, evidence: `Response took ${duration}ms` });
                        logs.push(`[CRITICAL] Possible Time-Based SQLi detected with payload: ${payload}`);
                    }
                } catch (err) {
                    if (err.response) {
                        const body = JSON.stringify(err.response.data);
                        const detectedErrors = sqlErrors.filter(errStr => body.includes(errStr));
                        if (detectedErrors.length > 0) {
                            findings.push({ type: 'Error-Based SQLi (HTTP Error)', payload, url: formUrl, evidence: detectedErrors[0] });
                            logs.push(`[CRITICAL] Possible SQLi detected in error response: ${payload}`);
                        }
                    }
                }
            });

            // Run form payload tests with concurrency of 5 and 100ms rate-limit delay
            await runWithConcurrency(formTasks, 5, 100);
        }

        // Test URL parameters
        const parsedUrl = url.parse(targetUrl, true);
        if (Object.keys(parsedUrl.query).length > 0) {
            logs.push(`[!] Testing URL parameters...`);
            
            const paramTasks = [];
            for (const param in parsedUrl.query) {
                for (const payload of payloads) {
                    paramTasks.push(async () => {
                        const testQuery = { ...parsedUrl.query };
                        testQuery[param] = payload;
                        const testUrl = url.format({ ...parsedUrl, search: null, query: testQuery });

                        try {
                            const startTime = Date.now();
                            const res = await axios.get(testUrl, { timeout: 10000 });
                            const endTime = Date.now();
                            const duration = endTime - startTime;

                            const body = res.data;
                            const detectedErrors = sqlErrors.filter(err => body.includes(err));

                            if (detectedErrors.length > 0) {
                                findings.push({ type: 'Error-Based SQLi (URL Param)', payload, url: testUrl, evidence: detectedErrors[0] });
                                logs.push(`[CRITICAL] Possible SQLi in URL param detected: ${payload}`);
                            }

                            if (duration > 5000 && (payload.includes('sleep') || payload.includes('SLEEP'))) {
                                findings.push({ type: 'Time-Based SQLi (URL Param)', payload, url: testUrl, evidence: `Response took ${duration}ms` });
                                logs.push(`[CRITICAL] Possible Time-Based SQLi in URL param detected: ${payload}`);
                            }
                        } catch (err) {
                            if (err.response) {
                                const body = JSON.stringify(err.response.data);
                                const detectedErrors = sqlErrors.filter(errStr => body.includes(errStr));
                                if (detectedErrors.length > 0) {
                                    findings.push({ type: 'Error-Based SQLi (URL Param / HTTP Error)', payload, url: testUrl, evidence: detectedErrors[0] });
                                    logs.push(`[CRITICAL] Possible SQLi in URL param detected in error response: ${payload}`);
                                }
                            }
                        }
                    });
                }
            }
            
            // Run URL param tests with concurrency of 5 and 100ms rate-limit delay
            await runWithConcurrency(paramTasks, 5, 100);
        }

    } catch (error) {
        logs.push(`[ERROR] Failed to fetch target: ${error.message}`);
    }

    logs.push(`[*] Scan completed. Found ${findings.length} potential vulnerabilities.`);
    return { findings, logs };
}

app.post('/api/scan', async (req, res) => {
    const { targetUrl } = req.body;
    if (!targetUrl) return res.status(400).json({ error: 'URL is required' });

    const result = await scanURL(targetUrl);
    res.json(result);
});

app.listen(PORT, () => {
    console.log(`Scanner server running on http://localhost:${PORT}`);
});
