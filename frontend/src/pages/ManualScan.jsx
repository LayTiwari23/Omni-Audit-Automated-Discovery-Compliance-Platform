import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api';
import toast from 'react-hot-toast';
import Modal from '../components/ui/Modal';
import { 
  PlusIcon, 
  TrashIcon, 
  ShieldCheckIcon, 
  QuestionMarkCircleIcon,
  DocumentTextIcon,
  AdjustmentsIcon,
  CheckIcon,
  ArrowRightIcon,
  ChevronLeftIcon,
  CursorClickIcon
} from '@heroicons/react/outline';
import { cn } from '../utils/cn';

const ENGINES = [
  { id: 'web', label: 'Web (HTTP/HTTPS)' },
  { id: 'network', label: 'Network (Ports/Services)' },
  { id: 'dns', label: 'DNS (Records/Security)' },
  { id: 'email', label: 'Email (MX/SPF/DMARC)' },
  { id: 'ssh', label: 'SSH (Hardening)' },
  { id: 'ftp', label: 'FTP (Security)' },
  { id: 'vpn', label: 'VPN (Security)' },
];

export default function ManualScan() {
  const navigate = useNavigate();
  const [step, setStep] = useState('group'); // group, configure
  const [groupName, setGroupName] = useState('');
  const [groupDesc, setGroupDesc] = useState('');
  const [groupId, setGroupId] = useState(null);
  
  const [scanRows, setScanRows] = useState([
    { target: '', engine: 'web', port: '', emailFrom: '', emailTo: '' }
  ]);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showAccessDeniedModal, setShowAccessDeniedModal] = useState(false);

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
      setStep('configure');
      toast.success('Campaign created');
    } catch (err) {
      toast.error('Failed to create campaign');
      setError(err.response?.data?.detail || 'Failed to create campaign');
    } finally {
      setLoading(false);
    }
  };

  const addRow = () => {
    setScanRows([...scanRows, { target: '', engine: 'web', port: '', emailFrom: '', emailTo: '' }]);
  };

  const removeRow = (index) => {
    if (scanRows.length === 1) return;
    const newRows = [...scanRows];
    newRows.splice(index, 1);
    setScanRows(newRows);
  };

  const updateRow = (index, field, value) => {
    const newRows = [...scanRows];
    newRows[index][field] = value;
    setScanRows(newRows);
  };

  const startScans = async () => {
    const validRows = scanRows.filter(r => r.target.trim());
    if (validRows.length === 0) {
      toast.error('Please enter at least one target');
      return;
    }

    setLoading(true);
    setError('');
    
    try {
      const selections = validRows.map(r => ({
        target: r.target.trim(),
        engine: r.engine,
        port: r.port ? parseInt(r.port) : (r.engine === 'web' ? 443 : (r.engine === 'ssh' ? 22 : (r.engine === 'ftp' ? 21 : 0)))
      }));

      const emailRow = validRows.find(r => r.engine === 'email');
      const emailOptions = emailRow ? { from: emailRow.emailFrom, to: emailRow.emailTo } : null;

      const payload = {
        selections,
        email_options: emailOptions
      };

      await api.post(`/scan_groups/${groupId}/scans/start`, payload);
      toast.success('Manual scans started successfully');
      navigate('/reports');
    } catch (err) {
      if (err.response?.status === 403) {
        setShowAccessDeniedModal(true);
        setError('Access Denied: You are not authorized to perform scans on these targets.');
      } else {
        toast.error('Failed to start scans');
        setError(err.response?.data?.detail || 'Failed to start scans');
      }
    } finally {
      setLoading(false);
    }
  };

  const steps = [
    { id: 'group', label: 'Campaign Details', icon: DocumentTextIcon },
    { id: 'configure', label: 'Configuration', icon: AdjustmentsIcon },
  ];

  const currentStepIndex = steps.findIndex(s => s.id === step);

  return (
    <div className="min-h-full bg-gradient-to-br from-blue-50 to-gray-50 -m-8 p-8 animate-fadeIn">
      {/* 1. Header Section */}
      <div className="max-w-7xl mx-auto mb-10 flex justify-between items-center">
        <div className="flex items-center gap-4">
          <div className="w-14 h-14 bg-white rounded-2xl shadow-sm flex items-center justify-center border border-blue-100">
            <CursorClickIcon className="w-8 h-8 text-primary-600" />
          </div>
          <div>
            <h1 className="text-3xl font-black text-gray-900 tracking-tight">Manual Scan Campaign</h1>
            <p className="text-gray-500 font-medium mt-1">Direct execution of scans without discovery phase</p>
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
          <div className="flex items-center justify-center gap-20 relative px-10">
            {/* Background Line */}
            <div className="absolute left-1/4 right-1/4 top-1/2 -translate-y-1/2 h-0.5 bg-gray-100 -z-10"></div>
            
            {steps.map((s, idx) => {
              const isActive = idx === currentStepIndex;
              const isCompleted = idx < currentStepIndex;
              const Icon = s.icon;
              
              return (
                <div key={s.id} className="flex flex-col items-center gap-3 relative min-w-[120px]">
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
            <div className={cn("w-full mx-auto transition-all duration-500", step === 'configure' ? "max-w-6xl" : "max-w-2xl")}>
              
              {step === 'group' && (
                <div className="space-y-8 animate-slideIn">
                  <div className="space-y-1 text-center">
                    <h2 className="text-2xl font-black text-gray-900 tracking-tight">Campaign Details</h2>
                    <p className="text-gray-500 font-medium">Provide basic information about your manual scan campaign</p>
                  </div>

                  <div className="space-y-6">
                    <div className="space-y-2">
                      <label className="text-xs font-black text-gray-400 uppercase tracking-widest px-1">Campaign Name</label>
                      <input 
                        type="text" 
                        value={groupName} 
                        onChange={(e) => setGroupName(e.target.value)} 
                        placeholder="e.g., Manual API Security Check" 
                        className="w-full px-5 py-4 bg-gray-50 border border-gray-200 rounded-2xl focus:bg-white focus:ring-4 focus:ring-primary-500/10 focus:border-primary-500 outline-none transition-all text-gray-900 font-medium text-lg placeholder:text-gray-300 shadow-sm"
                      />
                    </div>

                    <div className="space-y-2">
                      <label className="text-xs font-black text-gray-400 uppercase tracking-widest px-1">Description (Optional)</label>
                      <textarea 
                        value={groupDesc} 
                        onChange={(e) => setGroupDesc(e.target.value)} 
                        rows="4" 
                        placeholder="Describe the context of these manual scans..." 
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
                            Continue to Configuration
                            <ArrowRightIcon className="w-5 h-5" />
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {step === 'configure' && (
                <div className="space-y-8 animate-slideIn">
                  <div className="space-y-1">
                    <h2 className="text-2xl font-black text-gray-900 tracking-tight">Configure Targets & Engines</h2>
                    <p className="text-gray-500 font-medium">Add targets and select corresponding security engines</p>
                  </div>

                  <div className="space-y-4">
                    {scanRows.map((row, idx) => (
                      <div key={idx} className="group relative p-6 bg-white border border-gray-100 rounded-[24px] shadow-sm hover:shadow-md hover:border-primary-100 transition-all duration-300">
                        <div className="grid grid-cols-12 gap-6 items-end">
                          <div className="col-span-12 lg:col-span-5 space-y-2">
                            <label className="text-[10px] font-black text-gray-400 uppercase tracking-widest px-1">Target Asset (IP or Domain)</label>
                            <input
                              type="text"
                              value={row.target}
                              onChange={(e) => updateRow(idx, 'target', e.target.value)}
                              className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-xl focus:bg-white focus:ring-2 focus:ring-primary-500/10 focus:border-primary-500 outline-none transition-all text-sm font-bold"
                              placeholder="e.g. 1.2.3.4 or domain.com"
                            />
                          </div>
                          
                          <div className="col-span-12 sm:col-span-6 lg:col-span-4 space-y-2">
                            <label className="text-[10px] font-black text-gray-400 uppercase tracking-widest px-1">Security Engine</label>
                            <select
                              value={row.engine}
                              onChange={(e) => updateRow(idx, 'engine', e.target.value)}
                              className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-xl focus:bg-white focus:ring-2 focus:ring-primary-500/10 focus:border-primary-500 outline-none transition-all text-sm font-bold appearance-none"
                            >
                              {ENGINES.map(e => (
                                <option key={e.id} value={e.id}>{e.label}</option>
                              ))}
                            </select>
                          </div>

                          <div className="col-span-12 sm:col-span-4 lg:col-span-2 space-y-2">
                            <label className="text-[10px] font-black text-gray-400 uppercase tracking-widest px-1">Port</label>
                            <input
                              type="text"
                              value={row.port}
                              onChange={(e) => updateRow(idx, 'port', e.target.value)}
                              className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-xl focus:bg-white focus:ring-2 focus:ring-primary-500/10 focus:border-primary-500 outline-none transition-all text-sm font-bold text-center"
                              placeholder="Auto"
                            />
                          </div>

                          <div className="col-span-12 sm:col-span-2 lg:col-span-1 flex justify-center">
                            <button 
                              onClick={() => removeRow(idx)}
                              disabled={scanRows.length === 1}
                              className="p-3 text-rose-400 hover:text-rose-600 hover:bg-rose-50 rounded-xl transition-all disabled:opacity-0"
                              title="Remove Target"
                            >
                              <TrashIcon className="w-6 h-6" />
                            </button>
                          </div>
                        </div>

                        {row.engine === 'email' && (
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 mt-6 pt-6 border-t border-gray-50">
                            <div className="space-y-2">
                              <label className="text-[10px] font-black text-gray-400 uppercase tracking-widest px-1">From Identifier (Optional)</label>
                              <input
                                type="email"
                                value={row.emailFrom}
                                onChange={(e) => updateRow(idx, 'emailFrom', e.target.value)}
                                className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-xl focus:bg-white focus:ring-2 focus:ring-primary-500/10 focus:border-primary-500 outline-none transition-all text-sm font-medium"
                                placeholder="sender@example.com"
                              />
                            </div>
                            <div className="space-y-2">
                              <label className="text-[10px] font-black text-gray-400 uppercase tracking-widest px-1">Target Address(es) (Optional)</label>
                              <input
                                type="text"
                                value={row.emailTo}
                                onChange={(e) => updateRow(idx, 'emailTo', e.target.value)}
                                className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-xl focus:bg-white focus:ring-2 focus:ring-primary-500/10 focus:border-primary-500 outline-none transition-all text-sm font-medium"
                                placeholder="recipient@example.com"
                              />
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>

                  <div className="pt-8 border-t border-gray-100 flex items-center justify-between">
                    <button 
                      onClick={() => setStep('group')}
                      className="px-8 py-4 rounded-2xl font-black text-sm text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-all uppercase tracking-widest flex items-center gap-2"
                    >
                      <ChevronLeftIcon className="w-5 h-5" />
                      Back
                    </button>
                    
                    <div className="flex items-center gap-6">
                      <button 
                        onClick={addRow}
                        className="flex items-center gap-2 px-6 py-4 bg-white border border-gray-200 text-gray-600 rounded-2xl font-black text-xs uppercase tracking-widest hover:border-primary-300 hover:text-primary-600 transition-all shadow-sm"
                      >
                        <PlusIcon className="w-5 h-5" /> Add Target
                      </button>
                      
                      <button 
                        onClick={startScans} 
                        disabled={loading}
                        className="bg-gradient-to-r from-primary-600 to-blue-500 text-white px-12 py-5 rounded-2xl font-black text-xs uppercase tracking-widest shadow-[0_10px_25px_rgba(59,130,246,0.35)] hover:shadow-[0_15px_35px_rgba(59,130,246,0.45)] hover:-translate-y-1 active:scale-95 transition-all disabled:opacity-50 disabled:pointer-events-none"
                      >
                        {loading ? 'Initiating Scans...' : `Launch ${scanRows.filter(r=>r.target).length} Security Assessments`}
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

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
        .animate-slideIn {
          animation: slideIn 0.5s cubic-bezier(0.16, 1, 0.3, 1);
        }
        @keyframes slideIn {
          from { opacity: 0; transform: translateY(20px); }
          to { opacity: 1; transform: translateY(0); }
        }
        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        .animate-fadeIn {
          animation: fadeIn 0.8s ease-out;
        }
      `}} />
    </div>
  );
}
