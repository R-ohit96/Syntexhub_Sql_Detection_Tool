import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';

function App() {
  const [targetUrl, setTargetUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [logs, setLogs] = useState([]);
  const [findings, setFindings] = useState([]);
  const logEndRef = useRef(null);

  const scrollToBottom = () => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [logs]);

  const startScan = async () => {
    if (!targetUrl) return;

    setIsScanning(true);
    setLogs(['[*] Initializing engine...', '[*] Connecting to scanner server...']);
    setFindings([]);

    try {
      const response = await axios.post('http://localhost:5000/api/scan', { targetUrl });
      setLogs(prev => [...prev, ...response.data.logs]);
      setFindings(response.data.findings);
    } catch (error) {
      setLogs(prev => [...prev, `[ERROR] Connection failed: ${error.message}`]);
    } finally {
      setIsScanning(false);
    }
  };

  const getLogClass = (log) => {
    if (log.includes('[CRITICAL]')) return 'log-entry critical';
    if (log.includes('[+]') || log.includes('[*]')) return 'log-entry success';
    if (log.includes('[!]')) return 'log-entry info';
    return 'log-entry';
  };

  return (
    <div className="app-container">
      <div className="bg-glow glow-1"></div>
      <div className="bg-glow glow-2"></div>

      <header>
        <h1>VULN-SCAN PRO</h1>
        <p>Advanced SQL Injection Security Probe</p>
      </header>

      <div className="warning-box">
        <span style={{ fontSize: '1.5rem' }}>⚠️</span>
        <div>
          <strong>ETHICAL USE ONLY:</strong> Use this tool ONLY on applications you own or have explicit permission to test. Unauthorized scanning is illegal and unethical.
        </div>
      </div>

      <main className="glass-card">
        <div className="scanner-input-group">
          <input
            type="text"
            placeholder="Enter target URL (e.g., http://localhost/dvwa/login.php)"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            disabled={isScanning}
          />
          <button onClick={startScan} disabled={isScanning || !targetUrl}>
            {isScanning ? 'Scanning...' : 'Start Scan'}
          </button>
        </div>

        <div className="results-container">
          <div>
            <h2 style={{ marginBottom: '1rem', fontSize: '1.2rem', color: 'var(--accent-primary)' }}>Terminal Output</h2>
            <div className="log-panel">
              {logs.map((log, index) => (
                <div key={index} className={getLogClass(log)}>
                  {log}
                </div>
              ))}
              <div ref={logEndRef} />
            </div>
          </div>

          <div>
            <h2 style={{ marginBottom: '1rem', fontSize: '1.2rem', color: 'var(--danger)' }}>Vulnerabilities Detected ({findings.length})</h2>
            <div className="findings-panel">
              {findings.length === 0 && !isScanning && logs.length > 0 && (
                <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-dim)' }}>
                  No immediate vulnerabilities found in current pass.
                </div>
              )}
              {findings.map((finding, index) => (
                <div key={index} className="finding-card">
                  <h3>{finding.type}</h3>
                  <p><strong>Endpoint:</strong> {finding.url}</p>
                  <p><strong>Payload:</strong> {finding.payload}</p>
                  <div className="code-snip">
                    Evidence: {finding.evidence}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </main>

      <footer style={{ textAlign: 'center', marginTop: '3rem', color: 'var(--text-dim)', fontSize: '0.8rem' }}>
        &copy; 2026 VULN-SCAN PRO | SYNTECXHUB Cyber Division
      </footer>
    </div>
  );
}

export default App;
