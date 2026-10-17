import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api';
import LiveLogs from '../components/LiveLogs';
import toast from 'react-hot-toast';
import Modal from '../components/ui/Modal';
import Button from '../components/ui/Button';
import Input from '../components/ui/Input';
import ScanTypeBadge from '../components/ScanTypeBadge';
import { cn } from '../utils/cn';
import { 
  ShieldCheckIcon, 
  LightBulbIcon, 
  ArrowRightIcon, 
  CheckIcon, 
  DocumentTextIcon, 
  GlobeAltIcon, 
  QuestionMarkCircleIcon,
  TerminalIcon,
  CloudUploadIcon,
  ChevronLeftIcon,
  DocumentDownloadIcon
} from '@heroicons/react/outline';

export default function Scan() {
  const navigate = useNavigate();
  const [step, setStep] = useState('group'); // group, targets, discovery, select, email
  const [groupName, setGroupName] = useState('');
  const [groupDesc, setGroupDesc] = useState('');
  const [groupId, setGroupId] = useState(null);
  const [targetInput, setTargetInput] = useState('');
  const [inputMethod, setInputMethod] = useState('list');
  const [file, setFile] = useState(null);
  const [discoveryJobId, setDiscoveryJobId] = useState(null);
  const [discoveryStatus, setDiscoveryStatus] = useState(null);
  const [discoveryResults, setDiscoveryResults] = useState([]);
  const [selectedResults, setSelectedResults] = useState({});
  const [showEmailModal, setShowEmailModal] = useState(false);
  const [showAccessDeniedModal, setShowAccessDeniedModal] = useState(false);
  const [emailFrom, setEmailFrom] = useState('');
  const [emailTo, setEmailTo] = useState('');
  const [scanStarting, setScanStarting] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('supported'); // supported, unsupported, filtered, inactive
  const intervalRef = useRef(null);

  const createGroup = async () => {
    if (!groupName.trim()) {
      setError('Please enter a campaign name');
      return;
    }
    setLoading(true);
    setError('');
    try {
      const res = await api.post('/scan_groups', { name: groupName, description: groupDesc });
      setGroupId(res.data.id);
      setStep('targets');
      toast.success('Campaign created');
    } catch (err) {
      toast.error('Failed to create campaign');
      setError(err.response?.data?.detail || 'Failed to create campaign');
    } finally {
      setLoading(false);
    }
  };

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    if (selectedFile) {
      setFile(selectedFile);
      const reader = new FileReader();
      reader.onload = (event) => setTargetInput(event.target.result);
      reader.readAsText(selectedFile);
    }
  };

  const startDiscovery = async () => {
    if (!targetInput.trim()) {
      setError('Please enter targets');
      return;
    }
    setLoading(true);
    setError('');
    try {
      const response = await api.post(`/scan_groups/${groupId}/discover`, { raw_input: targetInput });
      const jobId = response.data.job_id;
      setDiscoveryJobId(jobId);
      setDiscoveryStatus({ status: 'pending', total: 0, processed: 0 });
      toast.success('Discovery started');
      if (intervalRef.current) clearInterval(intervalRef.current);
      intervalRef.current = setInterval(() => pollDiscovery(jobId), 2000);
      pollDiscovery(jobId);
      setStep('discovery');
    } catch (err) {
      if (err.response?.status === 403) {
        setShowAccessDeniedModal(true);
        setError('Access Denied: You are not authorized to perform scans on these targets. Please contact your administrator to request access permissions.');
      } else {
        toast.error('Discovery failed');
        setError(err.response?.data?.detail || 'Discovery failed');
      }
    } finally {
      setLoading(false);
    }
  };

  const pollDiscovery = async (jobId) => {
    try {
      const statusRes = await api.get(`/discover/${jobId}/status`);
      const status = statusRes.data;
      setDiscoveryStatus(status);
      if (status.status === 'completed' || status.status === 'failed') {
        if (intervalRef.current) clearInterval(intervalRef.current);
        intervalRef.current = null;
        if (status.status === 'completed') {
          toast.success('Discovery completed');
          setTimeout(async () => {
            const resultsRes = await api.get(`/discover/${jobId}/results`);
            const data = resultsRes.data;
            setDiscoveryResults(data);
            const selected = {};
            data.forEach((r, idx) => { 
              const isSupported = (r.state === 'open' || r.state === 'open|filtered') && r.engine !== 'unsupported' && r.port > 0;
              selected[idx] = isSupported; 
            });
            setSelectedResults(selected);
            setStep('select');
          }, 3000);
        } else {
          toast.error('Discovery failed');
          setError('Discovery failed');
        }
      }
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, []);

  const toggleSelectAll = () => {
    const filteredResults = discoveryResults.map((r, idx) => ({ ...r, originalIdx: idx })).filter(r => {
      if (activeTab === 'supported') return (r.state === 'open' || r.state === 'open|filtered') && r.engine !== 'unsupported' && r.port > 0;
      if (activeTab === 'unsupported') return r.engine === 'unsupported' && (r.state === 'open' || r.state === 'open|filtered');
      if (activeTab === 'filtered') return r.state === 'filtered';
      if (activeTab === 'inactive') return r.state === 'no_ports' || (r.port === 0 && r.service === 'none');
      return false;
    });

    if (filteredResults.length === 0) return;

    const allInTabSelected = filteredResults.every(r => selectedResults[r.originalIdx]);
    const newSelected = { ...selectedResults };
    
    filteredResults.forEach(r => {
      newSelected[r.originalIdx] = !allInTabSelected;
    });
    
    setSelectedResults(newSelected);
  };

  const downloadResults = () => {
    const csvContent = "data:text/csv;charset=utf-8," + 
      "IP,Domain,Port,Service,Engine,Version\n" +
      discoveryResults.map(r => [r.target_ip || '', r.target_domain || '', r.port, r.service, r.engine, r.version_info || ''].join(',')).join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", "discovery_results.csv");
    document.body.appendChild(link);
    link.click();
  };

  const executeScans = async (selections) => {
    setScanStarting(true);
    setError('');
    try {
      const payload = { selections, email_options: (emailFrom || emailTo) ? { from: emailFrom, to: emailTo } : null };
      await api.post(`/scan_groups/${groupId}/scans/start`, payload);
      toast.success('Scans started successfully');
      navigate('/reports');
    } catch (err) {
      if (err.response?.status === 403) {
        setShowAccessDeniedModal(true);
        setError('Access Denied: You are not authorized to perform scans on these targets. Please contact your administrator to request access permissions.');
      } else {
        toast.error('Failed to start scans');
        setError(err.response?.data?.detail || 'Failed to start scans');
      }
    } finally {
      setScanStarting(false);
    }
  };

  const startAutomatedScans = async () => {
    const selectedIndices = Object.entries(selectedResults).filter(([_, val]) => val).map(([idx]) => parseInt(idx));
    if (selectedIndices.length === 0) {
      setError('Please select at least one service');
      return;
    }
    const selections = selectedIndices.map(idx => ({
      target: discoveryResults[idx].target_domain || discoveryResults[idx].target_ip,
      port: discoveryResults[idx].port,
      engine: discoveryResults[idx].engine,
      service: discoveryResults[idx].service,
    }));
    const hasEmail = selections.some(s => s.engine === 'email');
    if (hasEmail) {
      setShowEmailModal(true);
      return;
    }
    await executeScans(selections);
  };

  const steps = [
    { id: 'group', label: 'Campaign Details', icon: DocumentTextIcon },
    { id: 'targets', label: 'Select Targets', icon: GlobeAltIcon },
    { id: 'discovery', label: 'Service Discovery', icon: TerminalIcon },
    { id: 'select', label: 'Finalize & Launch', icon: ShieldCheckIcon },
  ];

  const currentStepIndex = steps.findIndex(s => s.id === (step === 'email' ? 'select' : step));

  return (
    <div className="min-h-full bg-gradient-to-br from-blue-50 to-gray-50 -m-8 p-8 animate-fadeIn">
      {/* 1. Header Section */}
      <div className="max-w-7xl mx-auto mb-10 flex justify-between items-center">
        <div className="flex items-center gap-4">
          <div className="w-14 h-14 bg-white rounded-2xl shadow-sm flex items-center justify-center border border-blue-100">
            <ShieldCheckIcon className="w-8 h-8 text-primary-600" />
          </div>
          <div>
            <h1 className="text-3xl font-black text-gray-900 tracking-tight">New Scan Campaign</h1>
            <p className="text-gray-500 font-medium mt-1">Create a new security scan campaign to identify vulnerabilities</p>
          </div>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 border border-gray-200 rounded-xl text-sm font-bold text-gray-600 hover:bg-white hover:shadow-sm transition-all">
          <QuestionMarkCircleIcon className="w-5 h-5" />
          Need help?
        </button>
      </div>

      {/* 2. Top Progress Stepper (Horizontal) */}
      <div className="max-w-7xl mx-auto mb-8">
        <div className="bg-white/70 backdrop-blur-xl border border-white/40 shadow-sm rounded-3xl p-6">
          <div className="flex items-center justify-between relative px-10">
            {/* Background Line */}
            <div className="absolute left-20 right-20 top-1/2 -translate-y-1/2 h-0.5 bg-gray-100 -z-10"></div>
            
            {steps.map((s, idx) => {
              const isActive = idx === currentStepIndex;
              const isCompleted = idx < currentStepIndex;
              const Icon = s.icon;
              
              return (
                <div key={s.id} className="flex flex-col items-center gap-3 relative">
                  <div className={cn(
                    "w-12 h-12 rounded-full flex items-center justify-center transition-all duration-300 z-10 bg-white border-2",
                    isActive ? "border-primary-600 text-primary-600 shadow-[0_0_15px_rgba(59,130,246,0.3)] scale-110" : 
                    isCompleted ? "border-primary-500 bg-primary-500 text-white" : "border-gray-200 text-gray-300"
                  )}>
                    {isCompleted ? <CheckIcon className="w-6 h-6" /> : <Icon className="w-6 h-6" />}
                  </div>
                  <div className="flex flex-col items-center">
                    <span className={cn(
                      "text-[9px] font-black uppercase tracking-widest",
                      isActive ? "text-primary-600" : "text-gray-400"
                    )}>Step {idx + 1}</span>
                    <span className={cn(
                      "text-xs font-bold whitespace-nowrap",
                      isActive ? "text-gray-900" : "text-gray-400"
                    )}>{s.label}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* 3. Main Container */}
      <div className="max-w-7xl mx-auto">
        <div className="bg-white/70 backdrop-blur-xl border border-white/40 shadow-[0_20px_50px_rgba(0,0,0,0.05)] rounded-[32px] overflow-hidden min-h-[500px] flex flex-col">
          
          <div className="flex-1 p-10 flex flex-col overflow-hidden">
            <div className={cn("w-full mx-auto transition-all duration-500", (step === 'select' || step === 'discovery') ? "max-w-6xl" : "max-w-2xl")}>
              
              {step === 'group' && (
                <div className="space-y-8 animate-slideIn">
                  <div className="space-y-1">
                    <h2 className="text-2xl font-black text-gray-900 tracking-tight text-center">Campaign Details</h2>
                    <p className="text-gray-500 font-medium text-center">Provide basic information about your scan campaign</p>
                  </div>

                  <div className="space-y-6">
                    <div className="space-y-2">
                      <label className="text-xs font-black text-gray-400 uppercase tracking-widest">Campaign Name</label>
                      <input 
                        type="text" 
                        value={groupName} 
                        onChange={(e) => setGroupName(e.target.value)} 
                        placeholder="e.g., Q1 Infrastructure Security Audit" 
                        className="w-full px-5 py-4 bg-gray-50 border border-gray-200 rounded-2xl focus:bg-white focus:ring-4 focus:ring-primary-500/10 focus:border-primary-500 outline-none transition-all text-gray-900 font-medium text-lg placeholder:text-gray-300 shadow-sm"
                      />
                    </div>

                    <div className="space-y-2">
                      <label className="text-xs font-black text-gray-400 uppercase tracking-widest">Scope Description (Optional)</label>
                      <textarea 
                        value={groupDesc} 
                        onChange={(e) => setGroupDesc(e.target.value)} 
                        rows="4" 
                        placeholder="Briefly describe the assets and goals for this assessment..." 
                        className="w-full px-5 py-4 bg-gray-50 border border-gray-200 rounded-2xl focus:bg-white focus:ring-4 focus:ring-primary-500/10 focus:border-primary-500 outline-none transition-all text-gray-900 font-medium resize-none placeholder:text-gray-300 shadow-sm"
                      />
                    </div>

                    {error && <p className="text-sm font-bold text-rose-500 bg-rose-50 p-4 rounded-xl border border-rose-100">{error}</p>}

                    <div className="pt-4 flex items-center gap-4">
                      <button 
                        onClick={createGroup} 
                        disabled={loading}
                        className="flex-1 bg-gradient-to-r from-primary-600 to-blue-500 text-white px-8 py-4 rounded-2xl font-black text-sm uppercase tracking-widest shadow-[0_10px_20px_rgba(59,130,246,0.3)] hover:shadow-[0_15px_30px_rgba(59,130,246,0.4)] hover:-translate-y-0.5 active:scale-95 transition-all disabled:opacity-50 disabled:pointer-events-none flex items-center justify-center gap-2"
                      >
                        {loading ? 'Creating Campaign...' : (
                          <>
                            Continue to Targets
                            <ArrowRightIcon className="w-5 h-5" />
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {step === 'targets' && (
                <div className="space-y-8 animate-slideIn">
                  <div className="space-y-1">
                    <h2 className="text-2xl font-black text-gray-900 tracking-tight text-center">Configure Targets</h2>
                    <p className="text-gray-500 font-medium text-center">Define the IPs or domains you want to assess</p>
                  </div>

                  <div className="space-y-6">
                    <div className="flex bg-gray-100 p-1.5 rounded-2xl w-fit mx-auto">
                      <button 
                        onClick={() => setInputMethod('list')} 
                        className={cn(
                          "px-6 py-2 rounded-xl text-xs font-black uppercase tracking-widest transition-all",
                          inputMethod === 'list' ? "bg-white text-primary-600 shadow-sm" : "text-gray-400 hover:text-gray-600"
                        )}
                      >List Input</button>
                      <button 
                        onClick={() => setInputMethod('file')} 
                        className={cn(
                          "px-6 py-2 rounded-xl text-xs font-black uppercase tracking-widest transition-all",
                          inputMethod === 'file' ? "bg-white text-primary-600 shadow-sm" : "text-gray-400 hover:text-gray-600"
                        )}
                      >Upload File</button>
                    </div>

                    {inputMethod === 'list' ? (
                      <div className="space-y-2">
                        <label className="text-xs font-black text-gray-400 uppercase tracking-widest">Target List</label>
                        <textarea 
                          value={targetInput} 
                          onChange={(e) => setTargetInput(e.target.value)} 
                          rows="8" 
                          className="w-full px-5 py-4 bg-gray-50 border border-gray-200 rounded-2xl focus:bg-white focus:ring-4 focus:ring-primary-500/10 focus:border-primary-500 outline-none transition-all text-gray-900 font-mono text-sm placeholder:text-gray-300 resize-none shadow-sm" 
                          placeholder="192.168.1.1&#10;example.com&#10;10.0.0.0/24" 
                        />
                      </div>
                    ) : (
                      <div className="border-2 border-dashed border-gray-200 bg-gray-50/50 rounded-[32px] p-12 text-center group hover:border-primary-400 hover:bg-white transition-all cursor-pointer relative overflow-hidden">
                        <input type="file" onChange={handleFileChange} className="absolute inset-0 opacity-0 cursor-pointer z-10" id="fileUpload" />
                        <div className="space-y-4">
                          <div className="w-20 h-20 bg-white rounded-3xl shadow-sm border border-gray-100 flex items-center justify-center mx-auto group-hover:scale-110 transition-transform duration-500">
                            <CloudUploadIcon className="w-10 h-10 text-primary-500" />
                          </div>
                          <div>
                            <p className="text-lg font-black text-gray-900">{file ? file.name : 'Drop your targets file here'}</p>
                          </div>
                        </div>
                      </div>
                    )}

                    {error && <p className="text-sm font-bold text-rose-500 bg-rose-50 p-4 rounded-xl border border-rose-100">{error}</p>}

                    <div className="pt-4 flex items-center gap-4">
                      <button 
                        onClick={() => setStep('group')}
                        className="px-6 py-4 rounded-2xl font-black text-sm text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-all uppercase tracking-widest flex items-center gap-2"
                      >
                        <ChevronLeftIcon className="w-5 h-5" />
                        Back
                      </button>
                      <button 
                        onClick={startDiscovery} 
                        disabled={loading}
                        className="flex-1 bg-gradient-to-r from-primary-600 to-blue-500 text-white px-8 py-4 rounded-2xl font-black text-sm uppercase tracking-widest shadow-[0_10px_20px_rgba(59,130,246,0.3)] hover:shadow-[0_15px_30px_rgba(59,130,246,0.4)] hover:-translate-y-0.5 active:scale-95 transition-all disabled:opacity-50 disabled:pointer-events-none flex items-center justify-center gap-2"
                      >
                        {loading ? 'Analyzing Infrastructure...' : (
                          <>
                            Run Discovery Scan
                            <ArrowRightIcon className="w-5 h-5" />
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {step === 'discovery' && (
                <div className="space-y-8 animate-slideIn w-full">
                  <div className="space-y-1">
                    <h2 className="text-2xl font-black text-gray-900 tracking-tight text-center">Service Discovery in Progress</h2>
                    <p className="text-gray-500 font-medium text-center">Identifying active services and open ports on your targets</p>
                  </div>

                  <div className="bg-gray-50 rounded-[32px] p-8 border border-gray-100 shadow-inner">
                    <div className="flex items-center justify-between mb-4 px-2">
                      <span className="text-xs font-black text-primary-600 uppercase tracking-widest">Processing Assets</span>
                      <span className="text-xs font-black text-gray-400 uppercase tracking-widest">{discoveryStatus?.processed_targets} / {discoveryStatus?.total_targets} COMPLETE</span>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-5 mb-2 overflow-hidden shadow-inner p-1">
                      <div 
                        className="bg-gradient-to-r from-primary-600 to-blue-400 h-full rounded-full transition-all duration-1000 relative" 
                        style={{ width: `${(discoveryStatus?.processed_targets / (discoveryStatus?.total_targets || 1)) * 100}%` }}
                      >
                        <div className="absolute inset-0 bg-white/20 animate-shimmer"></div>
                      </div>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <div className="flex items-center gap-3">
                      <div className="w-2 h-2 rounded-full bg-primary-600 animate-pulse"></div>
                      <h3 className="text-xs font-black text-gray-400 uppercase tracking-widest">Real-time Scanner Log Output</h3>
                    </div>
                    <div className="rounded-[32px] overflow-hidden border-4 border-gray-100 shadow-2xl bg-black min-h-[450px]">
                      <LiveLogs discoveryId={discoveryJobId} status={discoveryStatus?.status} />
                    </div>
                  </div>
                </div>
              )}

              {step === 'select' && (
                <div className="space-y-8 animate-slideIn">
                   <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div className="space-y-1">
                      <h2 className="text-2xl font-black text-gray-900 tracking-tight">Discovery Results</h2>
                      <p className="text-gray-500 font-medium">Select services for deep compliance assessment</p>
                    </div>
                    <button onClick={downloadResults} className="flex items-center gap-2 px-5 py-2.5 bg-primary-50 text-primary-700 rounded-2xl text-[10px] font-black uppercase tracking-widest hover:bg-primary-100 transition-all border border-primary-100">
                      <DocumentDownloadIcon className="w-5 h-5" />
                      Export CSV Report
                    </button>
                  </div>

                  {/* Tabs from original design */}
                  <div className="flex flex-wrap gap-2 pb-2 border-b border-gray-100">
                    {[
                      { id: 'supported', label: 'Supported', count: discoveryResults.filter(r => (r.state === 'open' || r.state === 'open|filtered') && r.engine !== 'unsupported' && r.port > 0).length, color: 'primary' },
                      { id: 'unsupported', label: 'Unsupported', count: discoveryResults.filter(r => r.engine === 'unsupported' && (r.state === 'open' || r.state === 'open|filtered')).length, color: 'gray' },
                      { id: 'filtered', label: 'Filtered', count: discoveryResults.filter(r => r.state === 'filtered').length, color: 'warning' },
                      { id: 'inactive', label: 'Inactive', count: discoveryResults.filter(r => r.state === 'no_ports' || (r.port === 0 && r.service === 'none')).length, color: 'danger' }
                    ].map((tab) => (
                      <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={cn(
                          "flex items-center gap-2 px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all border shadow-sm",
                          activeTab === tab.id
                            ? `bg-primary-600 text-white border-transparent`
                            : `bg-white text-gray-500 border-gray-100 hover:border-primary-200 hover:bg-gray-50`
                        )}
                      >
                        {tab.label}
                        <span className={cn(
                          "px-2 py-0.5 rounded-md text-[9px]",
                          activeTab === tab.id ? 'bg-white/20 text-white' : 'bg-gray-100 text-gray-400'
                        )}>
                          {tab.count}
                        </span>
                      </button>
                    ))}
                  </div>

                  <div className="bg-white rounded-[32px] border border-gray-100 shadow-xl overflow-hidden">
                    <div className="overflow-x-auto">
                      <table className="min-w-full divide-y divide-gray-100">
                        <thead className="bg-gray-50/50">
                          <tr>
                            {activeTab === 'supported' && <th className="px-6 py-5 text-left text-[10px] font-black text-gray-400 uppercase tracking-widest">Select</th>}
                            <th className="px-6 py-5 text-left text-[10px] font-black text-gray-400 uppercase tracking-widest">Target Asset</th>
                            <th className="px-6 py-5 text-left text-[10px] font-black text-gray-400 uppercase tracking-widest">Port</th>
                            <th className="px-6 py-5 text-left text-[10px] font-black text-gray-400 uppercase tracking-widest">Service</th>
                            <th className="px-6 py-5 text-center text-[10px] font-black text-gray-400 uppercase tracking-widest">Engine</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-50 bg-white">
                          {discoveryResults
                            .filter(r => {
                              if (activeTab === 'supported') return (r.state === 'open' || r.state === 'open|filtered') && r.engine !== 'unsupported' && r.port > 0;
                              if (activeTab === 'unsupported') return r.engine === 'unsupported' && (r.state === 'open' || r.state === 'open|filtered');
                              if (activeTab === 'filtered') return r.state === 'filtered';
                              if (activeTab === 'inactive') return r.state === 'no_ports' || (r.port === 0 && r.service === 'none');
                              return false;
                            })
                            .map((result) => {
                              const originalIdx = discoveryResults.indexOf(result);
                              return (
                                <tr key={originalIdx} className={cn("transition-colors group", selectedResults[originalIdx] ? 'bg-primary-50/40' : 'hover:bg-gray-50/50')}>
                                  {activeTab === 'supported' && (
                                    <td className="px-6 py-5">
                                      <input 
                                        type="checkbox" 
                                        checked={selectedResults[originalIdx] || false} 
                                        onChange={() => setSelectedResults({ ...selectedResults, [originalIdx]: !selectedResults[originalIdx] })}
                                        className="w-6 h-6 rounded-lg border-gray-200 text-primary-600 focus:ring-primary-500/20 transition-all cursor-pointer shadow-sm"
                                      />
                                    </td>
                                  )}
                                  <td className="px-6 py-5 font-bold text-gray-900 text-sm tracking-tight">{result.target_ip || result.target_domain}</td>
                                  <td className="px-6 py-5">
                                    <span className="px-3 py-1 bg-gray-100 text-gray-700 rounded-lg text-xs font-black border border-gray-200 shadow-sm">{result.port || '---'}</span>
                                  </td>
                                  <td className="px-6 py-5 text-xs font-black text-gray-400 uppercase tracking-widest">{result.service}</td>
                                  <td className="px-6 py-5 text-center">
                                    <ScanTypeBadge type={result.engine} />
                                  </td>
                                </tr>
                              );
                            })}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  <div className="pt-8 border-t border-gray-100 flex items-center justify-between">
                    <button 
                      onClick={() => setStep('targets')}
                      className="px-8 py-4 rounded-2xl font-black text-sm text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-all uppercase tracking-widest flex items-center gap-2"
                    >
                      <ChevronLeftIcon className="w-5 h-5" />
                      Back
                    </button>
                    {activeTab === 'supported' && (
                      <div className="flex items-center gap-6">
                         <button onClick={toggleSelectAll} className="text-xs font-black text-gray-400 uppercase tracking-widest hover:text-primary-600 transition-all">
                           {discoveryResults
                            .map((r, idx) => ({ ...r, originalIdx: idx }))
                            .filter(r => (r.state === 'open' || r.state === 'open|filtered') && r.engine !== 'unsupported' && r.port > 0)
                            .every(r => selectedResults[r.originalIdx]) 
                            ? 'Deselect All' 
                            : 'Select All Results'}
                         </button>
                         <button 
                          onClick={startAutomatedScans} 
                          disabled={scanStarting}
                          className="bg-gradient-to-r from-primary-600 to-blue-500 text-white px-12 py-5 rounded-2xl font-black text-xs uppercase tracking-widest shadow-[0_10px_25px_rgba(59,130,246,0.35)] hover:shadow-[0_15px_35px_rgba(59,130,246,0.45)] hover:-translate-y-1 active:scale-95 transition-all disabled:opacity-50 disabled:pointer-events-none"
                        >
                          {scanStarting ? 'Initiating Security Assessments...' : `Launch ${Object.values(selectedResults).filter(v => v).length} Deep Scans`}
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              )}

            </div>
          </div>
        </div>
      </div>

      {/* Email Modal */}
      {showEmailModal && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-md overflow-y-auto h-full w-full z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-[40px] shadow-2xl w-full max-w-md overflow-hidden border border-gray-100 animate-slideIn">
            <div className="p-10">
              <h3 className="text-2xl font-black text-gray-900 mb-2 tracking-tight">Email Scan Parameters</h3>
              <p className="text-sm text-gray-500 mb-8 font-medium leading-relaxed">Required inputs for mail infrastructure assessment.</p>
              
              <div className="space-y-6">
                <div className="space-y-2">
                  <label className="text-[10px] font-black text-gray-400 uppercase tracking-[0.2em]">From Address</label>
                  <input 
                    type="email" 
                    value={emailFrom} 
                    onChange={(e) => setEmailFrom(e.target.value)} 
                    placeholder="scanner@certus.io" 
                    className="w-full px-6 py-4 bg-gray-50 border border-gray-200 rounded-2xl focus:bg-white focus:ring-4 focus:ring-primary-500/10 focus:border-primary-500 outline-none transition-all text-sm font-medium"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-[10px] font-black text-gray-400 uppercase tracking-[0.2em]">To Address</label>
                  <input 
                    type="text" 
                    value={emailTo} 
                    onChange={(e) => setEmailTo(e.target.value)} 
                    placeholder="security@target.com" 
                    className="w-full px-6 py-4 bg-gray-50 border border-gray-200 rounded-2xl focus:bg-white focus:ring-4 focus:ring-primary-500/10 focus:border-primary-500 outline-none transition-all text-sm font-medium"
                  />
                </div>
              </div>
            </div>
            <div className="bg-gray-50 px-10 py-8 flex justify-end gap-4 border-t border-gray-100">
              <button onClick={() => setShowEmailModal(false)} className="px-6 py-3 rounded-xl font-black text-xs text-gray-400 hover:text-gray-600 transition-all uppercase tracking-widest">Cancel</button>
              <button 
                onClick={() => {
                  const selectedIndices = Object.entries(selectedResults).filter(([_, val]) => val).map(([idx]) => parseInt(idx));
                  const selections = selectedIndices.map(idx => ({ 
                    target: discoveryResults[idx].target_domain || discoveryResults[idx].target_ip, 
                    port: discoveryResults[idx].port, 
                    engine: discoveryResults[idx].engine,
                    service: discoveryResults[idx].service
                  }));
                  executeScans(selections);
                  setShowEmailModal(false);
                }}
                className="bg-primary-600 text-white px-10 py-4 rounded-xl font-black text-xs uppercase tracking-widest shadow-lg shadow-primary-600/30 hover:bg-primary-700 transition-all"
              >Start Scans</button>
            </div>
          </div>
        </div>
      )}

      {/* Access Denied Modal */}
      <Modal
        isOpen={showAccessDeniedModal}
        onClose={() => setShowAccessDeniedModal(false)}
        title="Security Restriction"
      >
        <div className="text-sm text-gray-600 font-medium leading-relaxed">
          {error}
        </div>
      </Modal>

      {/* Global CSS for animations */}
      <style dangerouslySetInnerHTML={{ __html: `
        @keyframes shimmer {
          0% { transform: translateX(-100%); }
          100% { transform: translateX(100%); }
        }
        .animate-shimmer {
          animation: shimmer 2s infinite;
        }
        .animate-slideIn {
          animation: slideIn 0.5s cubic-bezier(0.16, 1, 0.3, 1);
        }
        @keyframes slideIn {
          from { opacity: 0; transform: translateY(20px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}} />
    </div>
  );
}
