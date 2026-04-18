/**
 * Securitia — Scanner UI
 * Terminal animation and progress display
 */

const severityIcons = {
  critical: '🔴',
  warning: '🟡',
  passed: '🟢',
};

const severityColors = {
  critical: 'error',
  warning: 'warning',
  passed: 'success',
};

export function initTerminal() {
  const terminalBody = document.getElementById('terminal-body');
  if (terminalBody) terminalBody.innerHTML = '';
}

export function addTerminalLine(text, type = 'dim', delay = 0) {
  return new Promise(resolve => {
    setTimeout(() => {
      const terminalBody = document.getElementById('terminal-body');
      if (!terminalBody) return resolve();

      const line = document.createElement('div');
      line.className = `terminal__line terminal__line--${type}`;
      line.textContent = text;
      terminalBody.appendChild(line);

      // Auto-scroll
      terminalBody.scrollTop = terminalBody.scrollHeight;
      resolve();
    }, delay);
  });
}

export async function runScanAnimation(url, results) {
  const terminalSection = document.getElementById('terminal-section');
  const terminalUrl = document.getElementById('terminal-url');
  const scannerInput = document.getElementById('scanner-input');

  terminalSection.hidden = false;
  terminalUrl.textContent = url;
  initTerminal();

  // Scroll to terminal
  terminalSection.scrollIntoView({ behavior: 'smooth', block: 'center' });

  // Initial lines
  await addTerminalLine(`$ securitia scan ${url}`, 'info', 100);
  await addTerminalLine('Initializing vulnerability scanner...', 'dim', 300);
  await addTerminalLine('', 'dim', 100);
  await addTerminalLine('─── Target Analysis ───', 'info', 400);
  await addTerminalLine(`Target: ${url}`, 'dim', 200);
  await addTerminalLine(`Timestamp: ${new Date().toISOString()}`, 'dim', 150);
  await addTerminalLine('', 'dim', 100);
  await addTerminalLine('─── Running Checks ───', 'info', 300);

  // Show each result as a terminal line
  for (let i = 0; i < results.length; i++) {
    const r = results[i];
    const icon = severityIcons[r.severity] || '⚪';
    const colorClass = severityColors[r.severity] || 'dim';
    const delay = 200 + Math.random() * 200;

    await addTerminalLine(
      `[${String(i + 1).padStart(2, '0')}/${String(results.length).padStart(2, '0')}] ${icon} ${r.name} — ${r.severity.toUpperCase()}`,
      colorClass,
      delay
    );
  }

  await addTerminalLine('', 'dim', 200);
  await addTerminalLine('─── Summary ───', 'info', 300);

  const criticalCount = results.filter(r => r.severity === 'critical').length;
  const warningCount = results.filter(r => r.severity === 'warning').length;
  const passedCount = results.filter(r => r.severity === 'passed').length;

  await addTerminalLine(`Critical: ${criticalCount}  |  Warnings: ${warningCount}  |  Passed: ${passedCount}`, 'dim', 200);
  await addTerminalLine('', 'dim', 100);
  await addTerminalLine('✓ Scan complete', 'success', 300);

  // Add scanning pulse to scanner input
  scannerInput?.classList.add('scanning');
  setTimeout(() => scannerInput?.classList.remove('scanning'), 3000);
}
