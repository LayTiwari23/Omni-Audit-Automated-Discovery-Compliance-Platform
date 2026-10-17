// src/pages/ReportDetail.jsx
import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
  RefreshIcon, 
  ChevronLeftIcon,
  DownloadIcon,
  ExclamationCircleIcon,
  CheckCircleIcon,
  ClockIcon,
  DocumentReportIcon,
  TableIcon,
  CodeIcon,
  StopIcon,
  PlayIcon,
  TerminalIcon,
  PencilIcon,
  SaveIcon,
  XIcon,
  DatabaseIcon,
  ArrowRightIcon
} from '@heroicons/react/outline';
import * as api from '../api/api';
import toast from 'react-hot-toast';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import CheckAccordion from '../components/CheckAccordion';
import LiveLogs from '../components/LiveLogs';
import ScanTypeBadge from '../components/ScanTypeBadge';
import { Card } from '../components/ui/Card';
import Button from '../components/ui/Button';
import { formatToIST } from '../utils/date';

// Proper names for web scan checks as per user requirement
const WEB_CHECK_NAMES = {
  1: "Port 80 and 443 are only open",
  2: "Website not operational over HTTP only",
  3: "Website operational over HTTPS only",
  4: "Header: Webserver version display disabled",
  5: "Header: PHP/CMS version display disabled",
  6: "Header: E-tag should not leak information",
  7: "Header: X-XSS-Protection enabled",
  8: "Header: X-Frame-Options enabled",
  9: "Header: Strict-Transport-Security enabled",
  10: "Header: Content-Security-Policy enabled",
  11: "Header: Cookies set as HttpOnly and Secure",
  12: "Header: Cookie Same-site set to Strict or Lax",
  13: "Header: Cache-control set properly",
  14: "Dangerous HTTP methods disabled",
  15: "Remote Login of CMS not accessible",
  16: "Deprecated SSL/TLS protocols disabled",
  17: "Weak Cipher support disabled",
  18: "Protected from POODLE attack",
  19: "Protected from Logjam attack",
  20: "Protected from Heartbleed bug",
  21: "Protected from CRIME vulnerability",
  22: "Protected from CCS Injection",
  23: "Protected from Anonymous Cipher",
  24: "Protected from FREAK attack",
  25: "Protected from DROWN attack",
  26: "Forward Secrecy supported",
  27: "HTTP/1.0 response blocked",
  28: "DNS CAA record setup",
};

export default function ReportDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(false);
  const [activeTab, setActiveTab] = useState('summary'); // summary, detailed
  const [editingRow, setEditingRow] = useState(null);
  const [editValues, setEditValues] = useState({});
  const [isSaving, setIsSaving] = useState(false);

  const fetchReport = useCallback(async () => {
    try {
      const data = await api.getReportDetails(id, true);
      setReport(data);
    } catch (err) {
      console.error("Failed to fetch report:", err);
    } finally {
      setLoading(false);
    }
  }, [id]);

  const handleDownload = async () => {
    setDownloading(true);
    try {
      await api.downloadReport(id);
    } catch (err) {
      console.error("Download failed:", err);
      alert("Failed to generate PDF report.");
    } finally {
      setDownloading(false);
    }
  };

  const handleStop = async () => {
    if (!window.confirm("Stop this running scan?")) return;
    try {
      await api.stopReport(id);
      fetchReport();
    } catch (err) {
      alert("Failed to stop scan: " + err.message);
    }
  };

  const handleResume = async () => {
    try {
      await api.resumeReport(id);
      fetchReport();
    } catch (err) {
      alert("Failed to resume scan: " + err.message);
    }
  };

  const handleEdit = (check) => {
    setEditingRow(check.check_id);
    setEditValues({
      result: check.result === 'Y' ? 'PASS' : (check.result === 'N' ? 'FAIL' : check.result),
      severity: check.severity,
      decision_logic: check.decision_logic
    });
  };

  const handleSave = async (checkId) => {
    setIsSaving(true);
    try {
      await api.updateReportResult(id, checkId, editValues);
      toast.success("Result updated successfully");
      setEditingRow(null);
      fetchReport();
    } catch (err) {
      toast.error(err.message || "Failed to update result");
    } finally {
      setIsSaving(false);
    }
  };

  const wasModified = (checkId) => {
    return report?.edit_history?.some(h => h.check_id === String(checkId));
  };

  useEffect(() => {
    fetchReport();
    
    // If scan is running, poll for status
    let interval;
    if (report?.status === 'RUNNING') {
      interval = setInterval(fetchReport, 3000);
    }
    
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [fetchReport, report?.status]);

  // Sort results by check_id to maintain Sr No consistency
  const sortedResults = useMemo(() => {
    if (!report?.results) return [];
    return [...report.results].sort((a, b) => a.check_id - b.check_id);
  }, [report?.results]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <RefreshIcon className="w-8 h-8 text-primary-500 animate-spin" />
      </div>
    );
  }

  if (!report) {
    return (
      <div className="text-center py-12">
        <ExclamationCircleIcon className="w-12 h-12 text-gray-400 mx-auto" />
        <h2 className="mt-2 text-lg font-medium text-gray-900">Report not found</h2>
        <Button 
          variant="link" 
          onClick={() => navigate('/reports')}
          className="mt-4"
        >
          Back to Reports
        </Button>
      </div>
    );
  }

  const stats = report.compliance_stats || {
    total_checks: 0,
    passed: 0,
    failed: 0,
    compliance_percent: 0
  };

  // Calculate severity counts
  const severityCounts = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0
  };

  sortedResults.forEach(check => {
    if (check.result === 'N') { // Only count failed checks for severity
      const sev = String(check.severity || '').toUpperCase();
      if (severityCounts.hasOwnProperty(sev)) {
        severityCounts[sev]++;
      }
    }
  });

  // Helper to get formatted check name
  const getCheckName = (check) => {
    if (report.scan_type === 'web' && WEB_CHECK_NAMES[check.check_id]) {
      return WEB_CHECK_NAMES[check.check_id];
    }
    return check.check_name;
  };

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* Redesigned Header Card */}
      <Card className="bg-white border border-gray-200 shadow-sm overflow-hidden">
        <div className="p-6">
          <div className="flex flex-col lg:flex-row justify-between gap-6">
            <div className="space-y-4 flex-1">
              <div className="flex items-center gap-2 mb-2">
                <button 
                  onClick={() => navigate('/reports')}
                  className="p-1.5 hover:bg-gray-100 rounded-full transition-colors"
                >
                  <ChevronLeftIcon className="w-5 h-5 text-gray-500" />
                </button>
                <span className="text-xs font-bold text-primary-600 uppercase tracking-widest">Compliance Report Detail</span>
              </div>
              
              <div>
                <p className="text-xs font-black text-gray-400 uppercase tracking-widest mb-1">Target Name</p>
                <h1 className="text-4xl font-black text-gray-900 tracking-tight">{report.domain}</h1>
              </div>

              <div className="flex flex-wrap gap-4 pt-2">
                <div className="bg-cyan-50 border border-cyan-100 rounded-2xl px-8 py-6 shadow-sm min-w-[160px] flex flex-col items-center text-center">
                  <p className="text-[12px] font-black text-cyan-600 uppercase tracking-widest mb-2">Port Number</p>
                  <p className="text-3xl font-black text-cyan-800 leading-none">{report.scan_metadata?.port || 'N/A'}</p>
                </div>
                <div className="bg-purple-50 border border-purple-100 rounded-2xl px-8 py-6 shadow-sm min-w-[180px] flex flex-col items-center text-center">
                  <p className="text-[12px] font-black text-purple-600 uppercase tracking-widest mb-2">Service Discovery</p>
                  <p className="text-3xl font-black text-purple-800 uppercase tracking-tighter leading-none">{report.scan_metadata?.service || report.scan_type || 'N/A'}</p>
                </div>
                <div className="bg-indigo-50 border border-indigo-100 rounded-2xl px-8 py-6 shadow-sm min-w-[220px] flex flex-col items-center text-center">
                  <p className="text-[12px] font-black text-indigo-600 uppercase tracking-widest mb-2">Compliance Engine</p>
                  <p className="text-3xl font-black text-indigo-800 uppercase tracking-tighter leading-none">{report.scan_type || 'N/A'}</p>
                </div>
                {report.scanner_ip && (
                  <div className="bg-emerald-50 border border-emerald-100 rounded-2xl px-8 py-6 shadow-sm min-w-[220px] flex flex-col items-center text-center">
                    <p className="text-[12px] font-black text-emerald-600 uppercase tracking-widest mb-2">Checks Performed By</p>
                    <p className="text-2xl font-black text-emerald-800 uppercase tracking-tighter leading-none flex items-center gap-2">
                      <span className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></span>
                      {report.scanner_ip}
                    </p>
                  </div>
                )}
              </div>

              <div className="bg-gray-50 rounded-xl p-1 border border-gray-100 shadow-inner">
                <div className="bg-white rounded-lg p-6 border border-gray-100 shadow-sm">
                  <p className="text-xs font-black text-gray-400 uppercase tracking-widest mb-4 border-b pb-2">Campaign Metadata</p>
                  <ul className="grid grid-cols-1 sm:grid-cols-2 gap-y-4 gap-x-8">
                    <li className="flex flex-col text-sm text-gray-600">
                      <span className="text-[10px] font-black text-primary-500 uppercase mb-1">Report Identity</span>
                      <span className="text-lg font-bold text-gray-900">ID #{report.id}</span>
                    </li>
                    <li className="flex flex-col text-sm text-gray-600">
                      <span className="text-[10px] font-black text-primary-500 uppercase mb-1">Execution Date</span>
                      <span className="text-lg font-bold text-gray-900">{formatToIST(report.created_at).split(' ')[0]}</span>
                    </li>
                    <li className="flex flex-col text-sm text-gray-600">
                      <span className="text-[10px] font-black text-primary-500 uppercase mb-1">Execution Time</span>
                      <span className="text-lg font-bold text-gray-900">{formatToIST(report.created_at).split(' ').slice(1).join(' ')}</span>
                    </li>
                    <li className="flex flex-col text-sm text-gray-600">
                      <span className="text-[10px] font-black text-primary-500 uppercase mb-1">Assessment Status</span>
                      <span className="text-lg font-bold text-gray-900 uppercase tracking-wide">{report.status}</span>
                    </li>
                  </ul>
                </div>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row lg:flex-col items-center justify-center gap-3">
              {report.status === 'RUNNING' && (
                <Button 
                  variant="outline" 
                  size="lg" 
                  onClick={handleStop}
                  className="w-full text-warning-600 border-warning-200 hover:bg-warning-50 shadow-sm"
                >
                  <StopIcon className="w-5 h-5 mr-2" />
                  Stop Scan
                </Button>
              )}
              {(report.status === 'CANCELLED' || report.status === 'FAILED') && (
                <Button 
                  variant="outline" 
                  size="lg" 
                  onClick={handleResume}
                  className="w-full text-success-600 border-success-200 hover:bg-success-50 shadow-sm"
                >
                  <PlayIcon className="w-5 h-5 mr-2" />
                  Resume Scan
                </Button>
              )}
              <Button 
                variant="primary" 
                size="lg" 
                onClick={handleDownload}
                disabled={report.status !== 'COMPLETED' || downloading}
                className="w-full shadow-lg"
              >
                {downloading ? (
                  <RefreshIcon className="w-5 h-5 mr-2 animate-spin" />
                ) : (
                  <DownloadIcon className="w-5 h-5 mr-2" />
                )}
                Download Report
              </Button>
            </div>
          </div>
        </div>
      </Card>

      {/* Summary Stats Row 1 */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-white border-l-4 border-l-primary-500 shadow-sm">
          <div className="flex items-center gap-3">
            <DocumentReportIcon className="w-8 h-8 text-primary-500" />
            <div>
              <p className="text-xs font-bold text-gray-500 uppercase tracking-wider">Total Checks</p>
              <p className="text-2xl font-bold text-gray-900">{stats.total_checks}</p>
            </div>
          </div>
        </Card>
        <Card className="bg-white border-l-4 border-l-success-500 shadow-sm">
          <div className="flex items-center gap-3">
            <CheckCircleIcon className="w-8 h-8 text-success-500" />
            <div>
              <p className="text-xs font-bold text-gray-500 uppercase tracking-wider">Passed</p>
              <p className="text-2xl font-bold text-gray-900">{stats.passed}</p>
            </div>
          </div>
        </Card>
        <Card className="bg-white border-l-4 border-l-danger-500 shadow-sm">
          <div className="flex items-center gap-3">
            <ExclamationCircleIcon className="w-8 h-8 text-danger-500" />
            <div>
              <p className="text-xs font-bold text-gray-500 uppercase tracking-wider">Failed</p>
              <p className="text-2xl font-bold text-gray-900">{stats.failed}</p>
            </div>
          </div>
        </Card>
        <Card className="bg-white border-l-4 border-l-indigo-500 shadow-sm">
          <div className="flex items-center gap-3">
            <div className="relative w-10 h-10">
              <svg className="w-full h-full" viewBox="0 0 36 36">
                <circle cx="18" cy="18" r="16" fill="none" className="stroke-current text-gray-200" strokeWidth="3" />
                <circle cx="18" cy="18" r="16" fill="none" className="stroke-current text-indigo-500" strokeWidth="3" 
                  strokeDasharray={`${stats.compliance_percent}, 100`} transform="rotate(-90 18 18)" />
              </svg>
              <div className="absolute inset-0 flex items-center justify-center">
                <span className="text-[10px] font-bold">{Math.round(stats.compliance_percent)}%</span>
              </div>
            </div>
            <div>
              <p className="text-xs font-bold text-gray-500 uppercase tracking-wider">Compliance</p>
              <p className="text-2xl font-bold text-gray-900">{stats.compliance_percent}%</p>
            </div>
          </div>
        </Card>
      </div>

      {/* Summary Stats Row 2 (Severity Counts) */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="bg-danger-50 border-l-4 border-l-danger-600 shadow-sm">
          <div>
            <p className="text-[10px] font-black text-danger-800 uppercase tracking-widest">Critical</p>
            <p className="text-3xl font-black text-gray-900 leading-none mt-1">{severityCounts.CRITICAL}</p>
          </div>
        </Card>
        <Card className="bg-danger-50/50 border-l-4 border-l-danger-400 shadow-sm">
          <div>
            <p className="text-[10px] font-black text-danger-700 uppercase tracking-widest">High</p>
            <p className="text-3xl font-black text-gray-800 leading-none mt-1">{severityCounts.HIGH}</p>
          </div>
        </Card>
        <Card className="bg-warning-50 border-l-4 border-l-warning-500 shadow-sm">
          <div>
            <p className="text-[10px] font-black text-warning-800 uppercase tracking-widest">Medium</p>
            <p className="text-3xl font-black text-warning-900 leading-none mt-1">{severityCounts.MEDIUM}</p>
          </div>
        </Card>
        <Card className="bg-success-50 border-l-4 border-l-success-500 shadow-sm">
          <div>
            <p className="text-[10px] font-black text-success-800 uppercase tracking-widest">Low</p>
            <p className="text-3xl font-black text-success-900 leading-none mt-1">{severityCounts.LOW}</p>
          </div>
        </Card>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {[
            { id: 'summary', label: 'Summary', icon: TableIcon },
            { id: 'detailed', label: 'Detailed Findings', icon: DocumentReportIcon },
            { id: 'live', label: 'Live Feed', icon: TerminalIcon },
            { id: 'audit', label: 'Audit Trail', icon: DatabaseIcon },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`
                flex items-center gap-2 py-4 px-1 border-b-2 font-medium text-sm transition-colors
                ${activeTab === tab.id 
                  ? 'border-primary-500 text-primary-600' 
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'}
              `}
            >
              <tab.icon className="w-5 h-5" />
              {tab.label}
              {tab.id === 'audit' && report?.edit_history?.length > 0 && (
                <span className="ml-1 px-1.5 py-0.5 bg-primary-100 text-primary-700 text-[10px] font-bold rounded-full">
                  {report.edit_history.length}
                </span>
              )}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="pb-12">
        {activeTab === 'summary' && (
          <Card padding="p-0 overflow-hidden">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Sr No</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Check Name</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Remarks</th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap">Actions</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {sortedResults.map((check, index) => {
                  const isEditing = editingRow === check.check_id;
                  const modified = wasModified(check.check_id);
                  
                  return (
                    <tr key={check.check_id} className={`
                      ${check.result === 'FAIL' || check.result === 'N' ? 'bg-danger-50/30' : ''}
                      ${modified ? 'border-l-4 border-l-warning-400' : ''}
                    `}>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 font-mono">
                        {index + 1}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                        <div className="flex items-center gap-2">
                          {getCheckName(check)}
                          {modified && (
                            <span title="Manually edited">
                              <PencilIcon className="w-3 h-3 text-warning-600" />
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {isEditing ? (
                          <select 
                            className="text-xs border-gray-300 rounded focus:ring-primary-500 focus:border-primary-500"
                            value={editValues.result}
                            onChange={(e) => setEditValues({...editValues, result: e.target.value})}
                          >
                            <option value="PASS">PASS (Y)</option>
                            <option value="FAIL">FAIL (N)</option>
                          </select>
                        ) : (
                          <StatusBadge status={check.result} size="sm" />
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {isEditing ? (
                          <select 
                            className="text-xs border-gray-300 rounded focus:ring-primary-500 focus:border-primary-500"
                            value={editValues.severity || ""}
                            onChange={(e) => setEditValues({...editValues, severity: e.target.value || null})}
                          >
                            <option value="">N/A</option>
                            <option value="CRITICAL">CRITICAL</option>
                            <option value="HIGH">HIGH</option>
                            <option value="MEDIUM">MEDIUM</option>
                            <option value="LOW">LOW</option>
                            <option value="INFO">INFO</option>
                          </select>
                        ) : (
                          <SeverityBadge severity={check.severity} size="sm" />
                        )}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-500">
                        {isEditing ? (
                          <textarea 
                            className="w-full text-xs border-gray-300 rounded focus:ring-primary-500 focus:border-primary-500 min-w-[200px]"
                            rows="2"
                            value={editValues.decision_logic}
                            onChange={(e) => setEditValues({...editValues, decision_logic: e.target.value})}
                          />
                        ) : (
                          <div className="max-w-xs truncate" title={check.decision_logic}>
                            {check.decision_logic}
                          </div>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                        {isEditing ? (
                          <div className="flex justify-end gap-2">
                            <button 
                              onClick={() => handleSave(check.check_id)}
                              disabled={isSaving}
                              className="text-success-600 hover:text-success-900 disabled:opacity-50"
                              title="Save"
                            >
                              <SaveIcon className="w-5 h-5" />
                            </button>
                            <button 
                              onClick={() => setEditingRow(null)}
                              className="text-gray-400 hover:text-gray-600"
                              title="Cancel"
                            >
                              <XIcon className="w-5 h-5" />
                            </button>
                          </div>
                        ) : (
                          <button 
                            onClick={() => handleEdit(check)}
                            className="text-primary-600 hover:text-primary-900"
                            title="Edit manually"
                          >
                            <PencilIcon className="w-4 h-4" />
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
                {(sortedResults.length === 0) && (
                  <tr>
                    <td colSpan="6" className="px-6 py-12 text-center text-gray-500 italic">
                      {report.status === 'RUNNING' ? 'Scan in progress, results will appear soon...' : 'No results found for this scan.'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </Card>
        )}

        {activeTab === 'audit' && (
           <div className="space-y-6">
              <div className="flex flex-col gap-1">
                <h3 className="text-lg font-black text-gray-900 tracking-tight uppercase">Manual Override Audit Trail</h3>
                <p className="text-sm text-gray-500 font-medium italic">History of manual status and severity corrections made to this scan report.</p>
              </div>

              {report?.edit_history?.length > 0 ? (
                <Card padding="p-0 overflow-hidden" className="border-indigo-100 shadow-xl ring-1 ring-black/5">
                  <table className="min-w-full divide-y divide-gray-200">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-6 py-4 text-left text-[10px] font-black text-gray-500 uppercase tracking-widest">Target Check</th>
                        <th className="px-6 py-4 text-left text-[10px] font-black text-gray-500 uppercase tracking-widest">Modified Field</th>
                        <th className="px-6 py-4 text-left text-[10px] font-black text-gray-500 uppercase tracking-widest">Original State</th>
                        <th className="px-2 py-4"></th>
                        <th className="px-6 py-4 text-left text-[10px] font-black text-gray-500 uppercase tracking-widest">New State</th>
                        <th className="px-6 py-4 text-right text-[10px] font-black text-gray-500 uppercase tracking-widest">Audit Attribution</th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-100">
                      {report.edit_history.map(item => (
                        <tr key={item.id} className="hover:bg-primary-50/30 transition-colors">
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex flex-col">
                              <span className="text-sm font-bold text-gray-900">Check #{item.check_id}</span>
                              <span className="text-[10px] text-gray-400 font-medium truncate max-w-[200px]">
                                {getCheckName({ check_id: item.check_id })}
                              </span>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-black uppercase bg-gray-100 text-gray-600 border border-gray-200">
                              {item.field_name}
                            </span>
                          </td>
                          <td className="px-6 py-4">
                            <span className="text-xs text-danger-600 bg-danger-50 px-2.5 py-1.5 rounded line-through opacity-60 font-mono border border-danger-100">
                              {item.old_value === null || item.old_value === 'None' ? 'EMPTY' : String(item.old_value)}
                            </span>
                          </td>
                          <td className="px-2 py-4 text-center">
                            <ArrowRightIcon className="w-5 h-5 text-gray-300 mx-auto" />
                          </td>
                          <td className="px-6 py-4">
                            <span className="text-xs text-success-800 bg-success-50 px-2.5 py-1.5 rounded font-black font-mono ring-2 ring-success-500/20 border border-success-200 shadow-sm">
                              {item.new_value === null || item.new_value === 'None' ? 'EMPTY' : String(item.new_value)}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-right">
                            <div className="flex flex-col items-end">
                              <span className="text-xs font-black text-gray-900">@{item.username}</span>
                              <span className="text-[10px] text-gray-500 font-bold uppercase tracking-tight">{formatToIST(item.created_at)}</span>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </Card>
              ) : (
                <div className="text-center py-20 bg-gray-50 rounded-xl border-2 border-dashed border-gray-200">
                  <DatabaseIcon className="w-12 h-12 text-gray-300 mx-auto mb-4" />
                  <p className="text-gray-500 font-medium">No manual overrides have been performed on this scan result.</p>
                </div>
              )}
           </div>
        )}

        {activeTab === 'detailed' && (
          <div className="space-y-4">
            {sortedResults.map((check, index) => (
              <CheckAccordion 
                key={check.check_id} 
                check={{...check, check_name: getCheckName(check)}} 
                index={index + 1} 
              />
            ))}
            {(sortedResults.length === 0) && (
              <div className="text-center py-12 text-gray-500 italic bg-white rounded-lg border border-gray-200">
                No detailed findings available yet.
              </div>
            )}
          </div>
        )}

        {activeTab === 'live' && (
          <LiveLogs scanId={report.id} status={report.status} />
        )}
      </div>
    </div>
  );
}
