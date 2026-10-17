// src/components/CheckAccordion.jsx
import { useState } from 'react';
import { Light as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vs2015 } from 'react-syntax-highlighter/dist/esm/styles/hljs';
import { CopyToClipboard } from 'react-copy-to-clipboard';
import { formatTimeIST } from '../utils/date';
import { CheckIcon, ClipboardCopyIcon } from '@heroicons/react/outline';
import toast from 'react-hot-toast';
import Badge from './ui/Badge';
import Button from './ui/Button';
import SeverityBadge from './SeverityBadge';
import { cn } from '../utils/cn';

// ─── Shared result helpers (also used by ReportDetail for the server view) ────
export function normalizeResult(result) {
  if (!result) return 'FAIL';
  const r = String(result).toUpperCase();
  if (r === 'PASS' || r === 'Y') return 'PASS';
  if (r === 'INCONCLUSIVE') return 'INCONCLUSIVE';
  return 'FAIL';
}

export function getResultVariant(result) {
  const r = normalizeResult(result);
  if (r === 'PASS') return 'success';
  if (r === 'INCONCLUSIVE') return 'warning';
  return 'danger';
}

export function ResultBadge({ result, className = '' }) {
  const variant = getResultVariant(result);
  return (
    <Badge variant={variant} size="sm" className={className}>
      {normalizeResult(result)}
    </Badge>
  );
}

// ─── Determine if raw output looks like JSON or plain text ─────────────────
function detectLanguage(raw) {
  if (!raw) return 'text';
  if (raw.trim().startsWith('{') || raw.trim().startsWith('[')) {
    try {
      JSON.parse(raw);
      return 'json';
    } catch {
      return 'text';
    }
  }
  if (raw.includes('nmap ') || raw.includes('curl ') || raw.includes('dig ')) {
    return 'bash';
  }
  return 'text';
}

export default function CheckAccordion({ check, index, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  const [copiedCmd, setCopiedCmd] = useState(false);
  const [copiedRaw, setCopiedRaw] = useState(false);

  // Support both legacy (command) and current (command_executed) field names
  const commandText = check.command_executed ?? check.command ?? null;
  const resultVariant = getResultVariant(check.result);
  const rawOutput = check.raw_output || '';
  const language = detectLanguage(rawOutput);

  const handleCopyCmd = () => {
    setCopiedCmd(true);
    toast.success('Command copied to clipboard');
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  const handleCopyRaw = () => {
    setCopiedRaw(true);
    toast.success('Raw output copied to clipboard');
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  return (
    <div className="border border-gray-200 rounded-xl overflow-hidden shadow-sm hover:shadow-md transition-shadow">
      {/* Header */}
      <button
        onClick={() => setOpen((o) => !o)}
        className={cn(
          'w-full flex items-center gap-3 px-4 py-4 bg-white hover:bg-gray-50 transition-colors text-left',
          open && 'border-b border-gray-200'
        )}
      >
        {/* Sequence number bubble */}
        <span className="w-8 h-8 rounded-full bg-primary-50 text-primary-700 text-sm font-bold flex items-center justify-center flex-shrink-0 font-mono">
          {index ?? check.check_id}
        </span>

        {/* Check name */}
        <span className="flex-1 text-sm font-medium text-gray-900 min-w-0">
          {check.check_name}
        </span>

        {/* Result badge */}
        <ResultBadge result={check.result} className="mr-2" />

        {/* Chevron */}
        <svg
          className={cn(
            'w-5 h-5 text-gray-400 flex-shrink-0 transition-transform duration-200',
            open ? 'rotate-180' : ''
          )}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Expanded content */}
      {open && (
        <div className="px-4 py-5 bg-gray-50 space-y-5">
          {/* Threat Enrichment */}
          {normalizeResult(check.result) !== 'PASS' && (check.severity || (check.cvss_score && check.cvss_score > 0) || check.cve_id) && (
            <div className="flex items-center gap-3 bg-white px-3 py-2 rounded-lg border border-gray-200">
              <div className="flex flex-col">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-gray-400 mb-0.5">Threat Level</p>
                <SeverityBadge severity={check.severity} />
              </div>
              {check.cvss_score > 0 && (
                <div className="flex flex-col border-l border-gray-100 pl-3">
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-gray-400 mb-0.5">CVSS Score</p>
                  <span className="text-sm font-bold text-gray-700">{check.cvss_score}</span>
                </div>
              )}
              {check.cve_id && (
                <div className="flex flex-col border-l border-gray-100 pl-3">
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-gray-400 mb-0.5">CVE ID</p>
                  <span className="text-sm font-medium text-primary-600">{check.cve_id}</span>
                </div>
              )}
            </div>
          )}

          {/* Tool & Command row */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {check.tool_name && (
              <div className="md:col-span-1">
                <p className="text-xs font-semibold uppercase tracking-wide text-gray-500 mb-1">
                  Tool
                </p>
                <p className="text-sm text-gray-800 font-mono bg-white px-3 py-2 rounded-lg border border-gray-200 truncate">
                  {check.tool_name}
                </p>
              </div>
            )}

            {check.execution_start && (
              <div className="md:col-span-1">
                <p className="text-xs font-semibold uppercase tracking-wide text-gray-500 mb-1">
                  Executed At (IST)
                </p>
                <p className="text-[13px] text-gray-800 font-mono bg-white px-3 py-2 rounded-lg border border-gray-200 truncate">
                  {formatTimeIST(check.execution_start)}
                </p>
              </div>
            )}

            {check.execution_duration !== undefined && (
              <div className="md:col-span-1">
                <p className="text-xs font-semibold uppercase tracking-wide text-gray-500 mb-1">
                  Duration
                </p>
                <p className="text-[13px] text-gray-800 font-mono bg-white px-3 py-2 rounded-lg border border-gray-200 truncate">
                  {Number(check.execution_duration).toFixed(2)}s
                </p>
              </div>
            )}

            {commandText && (
              <div className="md:col-span-1">
                <div className="flex items-center justify-between mb-1">
                  <p className="text-xs font-semibold uppercase tracking-wide text-gray-500">
                    Command
                  </p>
                  <CopyToClipboard text={commandText} onCopy={handleCopyCmd}>
                    <Button variant="ghost" size="sm" className="h-7 px-2">
                      {copiedCmd ? (
                        <CheckIcon className="w-4 h-4 text-success-600" />
                      ) : (
                        <ClipboardCopyIcon className="w-4 h-4 text-gray-500" />
                      )}
                      <span className="ml-1 text-xs">Copy</span>
                    </Button>
                  </CopyToClipboard>
                </div>
                <pre className="text-sm text-gray-800 font-mono bg-white px-3 py-2 rounded-lg border border-gray-200 overflow-x-auto whitespace-pre-wrap break-all">
                  {commandText}
                </pre>
              </div>
            )}
          </div>

          {/* Decision Logic */}
          {check.decision_logic && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide text-gray-500 mb-1">
                Decision Logic
              </p>
              <p className="text-sm text-gray-600 bg-white px-3 py-2 rounded-lg border border-gray-200 leading-relaxed">
                {check.decision_logic}
              </p>
            </div>
          )}

          {/* Remediation */}
          {check.remediation_text && (
            <div className="p-4 bg-blue-50 border border-blue-200 rounded-lg">
              <p className="text-[10px] font-semibold text-blue-800 uppercase tracking-wider mb-2">
                Remediation Guidance
              </p>
              <p className="text-sm text-gray-800 leading-relaxed">{check.remediation_text}</p>
              {check.remediation_example && (
                <div className="mt-3">
                  <p className="text-[10px] font-semibold text-blue-700 uppercase tracking-wider mb-1">Example / Config:</p>
                  <pre className="text-xs font-mono bg-white/50 p-2 rounded border border-blue-100 overflow-x-auto">
                    {check.remediation_example}
                  </pre>
                </div>
              )}
              {check.remediation_reference && (
                <div className="mt-3 flex items-center">
                  <a
                    href={check.remediation_reference}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs font-medium text-blue-600 hover:text-blue-800 flex items-center gap-1 transition-colors"
                  >
                    Documentation & Reference
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                    </svg>
                  </a>
                </div>
              )}
            </div>
          )}

          {/* Raw Output */}
          <div>
            <div className="flex items-center justify-end mb-1">
              {rawOutput && (
                <CopyToClipboard text={rawOutput} onCopy={handleCopyRaw}>
                  <Button variant="ghost" size="sm" className="h-7 px-2">
                    {copiedRaw ? (
                      <CheckIcon className="w-4 h-4 text-success-600" />
                    ) : (
                      <ClipboardCopyIcon className="w-4 h-4 text-gray-500" />
                    )}
                    <span className="ml-1 text-xs">Copy</span>
                  </Button>
                </CopyToClipboard>
              )}
            </div>
            {rawOutput ? (
              <div className="bg-[#1e1e1e] rounded-lg overflow-hidden border border-gray-800 shadow-xl">
                {/* Terminal Header */}
                <div className="bg-[#2d2d2d] px-4 py-2 flex items-center space-x-2 border-b border-white/5">
                  <div className="flex space-x-1.5">
                    <div className="w-3 h-3 rounded-full bg-[#ff5f56] shadow-sm" />
                    <div className="w-3 h-3 rounded-full bg-[#ffbd2e] shadow-sm" />
                    <div className="w-3 h-3 rounded-full bg-[#27c93f] shadow-sm" />
                  </div>
                  <div className="flex-1 text-center">
                    <span className="text-[10px] text-gray-400 font-mono uppercase tracking-widest opacity-50">
                      Raw Output
                    </span>
                  </div>
                  <div className="w-12" /> {/* Spacer to center the title */}
                </div>
                <SyntaxHighlighter
                  language={language}
                  style={vs2015}
                  customStyle={{
                    margin: 0,
                    padding: '1.25rem',
                    fontSize: '0.8rem',
                    maxHeight: '400px',
                    overflow: 'auto',
                    backgroundColor: 'transparent',
                  }}
                >
                  {rawOutput}
                </SyntaxHighlighter>
              </div>
            ) : (
              <p className="text-xs text-gray-400 italic bg-white px-3 py-2 rounded-lg border border-gray-200">
                Raw output not available – request with ?include_raw=true
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
