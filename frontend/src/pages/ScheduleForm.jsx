import React, { useState, useEffect, useMemo, useRef } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { getSchedule, createSchedule, updateSchedule, discoverServices, getDiscoveryStatus, getDiscoveryResults } from '../api/api';
import Button from '../components/ui/Button';
import Input from '../components/ui/Input';
import { Card, CardHeader, CardTitle, CardContent } from "../components/ui/Card";
import Spinner from '../components/ui/Spinner';
import toast from 'react-hot-toast';
import { 
  CalendarIcon, 
  ClockIcon, 
  RefreshIcon, 
  SearchIcon, 
  InformationCircleIcon,
  ChevronRightIcon,
  ChevronLeftIcon,
  TerminalIcon
} from '@heroicons/react/outline';
import LiveLogs from '../components/LiveLogs';
import Modal from '../components/ui/Modal';

const frequencies = [
  { id: 'daily', label: 'Daily', description: 'Run every day' },
  { id: 'weekly', label: 'Weekly', description: 'Run once a week' },
  { id: 'monthly', label: 'Monthly', description: 'Run once a month' },
  { id: 'once', label: 'One‑time', description: 'Specific date' },
];

const daysOfWeek = [
  { value: '1', label: 'Monday' }, { value: '2', label: 'Tuesday' }, { value: '3', label: 'Wednesday' },
  { value: '4', label: 'Thursday' }, { value: '5', label: 'Friday' }, { value: '6', label: 'Saturday' },
  { value: '0', label: 'Sunday' },
];

export default function ScheduleForm() {
  const { id } = useParams();
  const navigate = useNavigate();
  const isEditing = !!id;
  const intervalRef = useRef(null);

  const [step, setStep] = useState('details'); // details, discovery, schedule
  const [form, setForm] = useState({
    name: '',
    description: '',
    target: '',
    scan_type: 'auto',
    scan_mode: 'intelligent',
  });

  const [inputMethod, setInputMethod] = useState('list');
  const [discoveryJobId, setDiscoveryJobId] = useState(null);
  const [discoveryStatus, setDiscoveryStatus] = useState(null);
  const [discoveryResults, setDiscoveryResults] = useState([]);
  const [selectedResults, setSelectedResults] = useState({});
  const [showAccessDeniedModal, setShowAccessDeniedModal] = useState(false);
  const [error, setError] = useState('');

  // Schedule UI state
  const [scheduleType, setScheduleType] = useState('daily');
  const [time, setTime] = useState('02:00');
  const [date, setDate] = useState(new Date().toISOString().split('T')[0]);
  const [dayOfWeek, setDayOfWeek] = useState('1');
  const [dayOfMonth, setDayOfMonth] = useState('1');

  const [loading, setLoading] = useState(isEditing);
  const [saving, setSaving] = useState(false);
  const [activeTab, setActiveTab] = useState('supported'); // supported, unsupported, filtered, inactive

  const toggleRow = (idx) => setSelectedResults(prev => ({ ...prev, [idx]: !prev[idx] }));
  const toggleAll = () => {
    const allSelected = discoveryResults.length > 0 && 
      Object.values(selectedResults).every(v => v === true);
    const newSelected = {};
    discoveryResults.forEach((_, idx) => { newSelected[idx] = !allSelected; });
    setSelectedResults(newSelected);
  };

  // Helper to parse cron to human-readable state (UTC from backend -> IST for UI)
  const parseCron = (cron) => {
    try {
      const parts = cron.split(' ');
      if (parts.length !== 5) return;
      const [min, hour, dom, month, dow] = parts;
      
      // Convert UTC hour/min to IST
      let h = parseInt(hour, 10);
      let m = parseInt(min, 10);
      
      // Add 5h 30m for IST
      m += 30;
      if (m >= 60) { m -= 60; h += 1; }
      h += 5;
      if (h >= 24) h -= 24;

      setTime(`${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}`);
      
      if (dom === '*' && month === '*' && dow === '*') setScheduleType('daily');
      else if (dow !== '*') { setScheduleType('weekly'); setDayOfWeek(dow); }
      else if (dom !== '*' && month === '*') { setScheduleType('monthly'); setDayOfMonth(dom); }
      else if (dom !== '*' && month !== '*') {
        setScheduleType('once');
        setDate(`${new Date().getFullYear()}-${month.padStart(2, '0')}-${dom.padStart(2, '0')}`);
      }
    } catch (e) { console.error(e); }
  };

  const cronExpression = useMemo(() => {
    let [h, m] = time.split(':').map(s => parseInt(s, 10));
    
    // Convert IST to UTC for the backend cron
    // Subtract 5h 30m
    m -= 30;
    if (m < 0) { m += 60; h -= 1; }
    h -= 5;
    if (h < 0) h += 24;

    const hour = h.toString();
    const min = m.toString();

    switch (scheduleType) {
      case 'daily':   return `${min} ${hour} * * *`;
      case 'weekly':  return `${min} ${hour} * * ${dayOfWeek}`;
      case 'monthly': return `${min} ${hour} ${dayOfMonth} * *`;
      case 'once': {
        const d = new Date(date);
        return `${min} ${hour} ${d.getDate()} ${d.getMonth() + 1} *`;
      }
      default: return `${min} ${hour} * * *`;
    }
  }, [scheduleType, time, date, dayOfWeek, dayOfMonth]);

  useEffect(() => {
    if (isEditing) {
      const fetchSchedule = async () => {
        try {
          const data = await getSchedule(id);
          setForm({
            name: data.name,
            description: data.description || '',
            target: data.target,
            scan_type: data.scan_type,
            scan_mode: data.scan_mode,
          });
          parseCron(data.cron_expression);
        } catch (e) {
          toast.error("Failed to load schedule");
          navigate('/schedules');
        } finally { setLoading(false); }
      };
      fetchSchedule();
    }
  }, [id, isEditing, navigate]);

  const startDiscovery = async () => {
    if (!form.name.trim()) return toast.error("Please enter a campaign name");
    if (!form.target.trim()) return toast.error("Please enter targets");
    
    setLoading(true);
    try {
      // Use the standalone discovery endpoint
      const response = await discoverServices(form.target, inputMethod);
      const jobId = response.job_id;
      setDiscoveryJobId(jobId);
      setStep('discovery');
      intervalRef.current = setInterval(() => pollDiscovery(jobId), 2000);
    } catch (err) {
      if (err.response?.status === 403) {
        setError('Access Denied: You are not authorized to perform scans on these targets. Please contact your administrator to request access permissions.');
        setShowAccessDeniedModal(true);
      } else {
        toast.error(err.message || 'Discovery failed');
      }
    } finally { setLoading(false); }
  };

  const pollDiscovery = async (jobId) => {
    try {
      const res = await getDiscoveryStatus(jobId);
      setDiscoveryStatus(res);
      if (res.status === 'completed' || res.status === 'failed') {
        clearInterval(intervalRef.current);
        if (res.status === 'completed') {
          const results = await getDiscoveryResults(jobId);
          setDiscoveryResults(results);
          
          // Initialize all results as selected
          const selected = {};
          results.forEach((_, idx) => { selected[idx] = true; });
          setSelectedResults(selected);
          
          // Determine the detected engines
          if (results.length > 0) {
            const detectedEngines = [...new Set(results.map(r => r.engine))];
            const engineStr = detectedEngines.join(', ');
            setForm(prev => ({
              ...prev,
              scan_type: engineStr,
              // If we found specific engines, we can label the mode more specifically
              scan_mode: detectedEngines.length === 1 ? detectedEngines[0] : 'Auto-Discovery'
            }));
          }

          // Wait 2 seconds for user to see logs
          setTimeout(() => setStep('schedule'), 2000);
        }
      }
    } catch (err) { console.error(err); }
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => setForm(prev => ({ ...prev, target: event.target.result }));
      reader.readAsText(file);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      // Calculate dynamic scan_type and explicit selections
      const selectedIndices = Object.entries(selectedResults)
        .filter(([_, val]) => val)
        .map(([idx]) => parseInt(idx));
      
      let finalScanType = form.scan_type;
      let finalSelections = null;

      if (selectedIndices.length > 0 && discoveryResults.length > 0) {
        const selectedEngines = [...new Set(selectedIndices.map(idx => discoveryResults[idx].engine))];
        finalScanType = selectedEngines.join(', ');
        
        finalSelections = selectedIndices.map(idx => {
            const res = discoveryResults[idx];
            return {
                target: res.target_domain || res.target_ip,
                port: res.port,
                engine: res.engine,
                service: res.service,
                version: res.version_info
            };
        });
      }

      const payload = { 
        ...form, 
        scan_type: finalScanType, 
        cron_expression: cronExpression,
        discovery_job_id: discoveryJobId,
        selections: finalSelections
      };
      if (isEditing) await updateSchedule(id, payload);
      else await createSchedule(payload);
      toast.success(isEditing ? 'Schedule updated' : 'Schedule created');
      navigate('/schedules');
    } catch (err) {
      if (err.response?.status === 403) {
        setError('Access Denied: You are not authorized to perform scans on these targets. Please contact your administrator to request access permissions.');
        setShowAccessDeniedModal(true);
      } else {
        toast.error(err.message || 'Failed to save schedule');
      }
    } finally { setSaving(false); }
  };

  if (loading && isEditing) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-50">
        <Spinner size="lg" className="text-indigo-600" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-4xl mx-auto">
        <div className="mb-8 flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-extrabold text-gray-900 tracking-tight">
              {isEditing ? 'Edit Scheduled Campaign' : 'Schedule New Campaign'}
            </h1>
            <p className="text-gray-500 mt-2">Automate multi-target security assessments with intelligent auto-discovery.</p>
          </div>
          <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-widest text-gray-400">
            <span className={step === 'details' ? 'text-indigo-600' : ''}>Setup</span>
            <ChevronRightIcon className="w-3 h-3" />
            <span className={step === 'discovery' ? 'text-indigo-600' : ''}>Verify</span>
            <ChevronRightIcon className="w-3 h-3" />
            <span className={step === 'schedule' ? 'text-indigo-600' : ''}>Automate</span>
          </div>
        </div>

        {step === 'details' && (
          <div className="space-y-6 animate-fade-in">
            <Card>
              <CardHeader className="border-b bg-gray-50/50">
                <CardTitle className="text-lg">Campaign Information</CardTitle>
              </CardHeader>
              <CardContent className="p-6 space-y-4">
                <Input
                  label="Campaign Name"
                  value={form.name}
                  onChange={(e) => setForm({...form, name: e.target.value})}
                  required
                  placeholder="e.g. Weekly Production Audit"
                />
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Description (optional)</label>
                  <textarea
                    value={form.description}
                    onChange={(e) => setForm({...form, description: e.target.value})}
                    rows="2"
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-indigo-500 focus:border-indigo-500"
                    placeholder="Identify the scope of this recurring scan"
                  />
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="border-b bg-gray-50/50">
                <CardTitle className="text-lg">Targets</CardTitle>
              </CardHeader>
              <CardContent className="p-6">
                <div className="flex space-x-4 mb-4">
                  {['list', 'range', 'file'].map(m => (
                    <label key={m} className="inline-flex items-center cursor-pointer">
                      <input type="radio" checked={inputMethod === m} onChange={() => setInputMethod(m)} className="form-radio text-indigo-600" />
                      <span className="ml-2 text-sm text-gray-600 capitalize">{m === 'list' ? 'Comma List' : m === 'range' ? 'CIDR/Range' : 'File'}</span>
                    </label>
                  ))}
                </div>
                {inputMethod === 'file' && (
                  <input type="file" onChange={handleFileChange} className="mb-4 block w-full text-xs text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:bg-indigo-50 file:text-indigo-700" />
                )}
                <textarea
                  value={form.target}
                  onChange={(e) => setForm({...form, target: e.target.value})}
                  rows="5"
                  className="w-full border border-gray-300 rounded-lg p-3 text-sm font-mono focus:ring-indigo-500"
                  placeholder={inputMethod === 'range' ? "192.168.1.0/24" : "example.com, 1.2.3.4"}
                  required
                />
                <div className="mt-6 flex justify-end">
                  <Button onClick={startDiscovery} variant="primary" disabled={loading} className="px-10">
                    {loading ? 'Processing...' : 'Next: Verify Targets'}
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {step === 'discovery' && (
          <div className="space-y-6 animate-fade-in">
            <Card>
              <CardContent className="p-6">
                <h3 className="text-lg font-bold text-gray-900 mb-2">Verifying Infrastructure</h3>
                <p className="text-sm text-gray-500 mb-4">We are identifying active services on your targets to ensure the schedule runs correctly.</p>
                <div className="w-full bg-gray-100 rounded-full h-2 mb-2">
                  <div className="bg-indigo-600 h-2 rounded-full transition-all duration-500" style={{ width: `${(discoveryStatus?.processed_targets / (discoveryStatus?.total_targets || 1)) * 100}%` }}></div>
                </div>
                <p className="text-[10px] font-bold text-gray-400 uppercase">{discoveryStatus?.processed_targets} of {discoveryStatus?.total_targets} targets verified</p>
              </CardContent>
            </Card>
            {discoveryJobId && <LiveLogs discoveryId={discoveryJobId} status={discoveryStatus?.status} />}
          </div>
        )}

        {step === 'schedule' && (
          <form onSubmit={handleSubmit} className="space-y-6 animate-fade-in">
            {/* Tab Navigation Capsules */}
            {discoveryResults.length > 0 && (
              <div className="flex flex-wrap gap-2 pb-2 border-b">
                {[
                  { id: 'supported', label: 'Supported', count: discoveryResults.filter(r => (r.state === 'open' || r.state === 'open|filtered') && r.engine !== 'unsupported' && r.port > 0).length, color: 'indigo' },
                  { id: 'unsupported', label: 'Unsupported', count: discoveryResults.filter(r => r.engine === 'unsupported' && (r.state === 'open' || r.state === 'open|filtered')).length, color: 'gray' },
                  { id: 'filtered', label: 'Filtered', count: discoveryResults.filter(r => r.state === 'filtered').length, color: 'amber' },
                  { id: 'inactive', label: 'Inactive', count: discoveryResults.filter(r => r.state === 'no_ports' || (r.port === 0 && r.service === 'none')).length, color: 'red' }
                ].map((tab) => (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => setActiveTab(tab.id)}
                    className={`flex items-center gap-2 px-4 py-2 rounded-full text-xs font-bold uppercase tracking-wider transition-all border ${
                      activeTab === tab.id
                        ? `bg-${tab.color}-600 text-white border-${tab.color}-600 shadow-md`
                        : `bg-white text-gray-500 border-gray-200 hover:border-${tab.color}-300 hover:bg-${tab.color}-50`
                    }`}
                  >
                    {tab.label}
                    <span className={`px-2 py-0.5 rounded-full text-[10px] ${
                      activeTab === tab.id ? 'bg-white/20 text-white' : `bg-${tab.color}-50 text-${tab.color}-600`
                    }`}>
                      {tab.count}
                    </span>
                  </button>
                ))}
              </div>
            )}

            {/* Table 1: Supported Services */}
            {activeTab === 'supported' && discoveryResults.length > 0 && (
              <Card className="border-t-4 border-indigo-500">
                <CardHeader className="border-b bg-gray-50/50">
                  <CardTitle className="text-lg flex items-center justify-between">
                    <div>
                      <span className="block">Supported Services</span>
                      <span className="text-xs text-gray-400 font-normal">Select services to include in the recurring scan</span>
                    </div>
                    <button type="button" onClick={toggleAll} className="text-xs text-indigo-600 hover:text-indigo-800 font-bold uppercase">
                      {Object.values(selectedResults).every(v => v === true) ? 'Deselect All' : 'Select All'}
                    </button>
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-6 py-3 text-left">
                            <input 
                              type="checkbox" 
                              className="rounded text-indigo-600 focus:ring-indigo-500" 
                              checked={discoveryResults.length > 0 && Object.values(selectedResults).every(v => v === true)} 
                              onChange={toggleAll} 
                            />
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase">Target IP</th>
                          <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase">Domain</th>
                          <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase">Port</th>
                          <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase">Service</th>
                          <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase">Engine</th>
                          <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase">Version</th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-gray-100">
                        {discoveryResults
                          .filter(r => (r.state === 'open' || r.state === 'open|filtered') && r.engine !== 'unsupported' && r.port > 0)
                          .map((result) => {
                            const idx = discoveryResults.indexOf(result);
                            return (
                              <tr key={idx} className={`hover:bg-gray-50 transition-colors ${selectedResults[idx] ? 'bg-indigo-50/30' : ''}`}>
                                <td className="px-6 py-4">
                                  <input 
                                    type="checkbox" 
                                    className="rounded text-indigo-600 focus:ring-indigo-500" 
                                    checked={selectedResults[idx] || false} 
                                    onChange={() => toggleRow(idx)} 
                                  />
                                </td>
                                <td className="px-6 py-4 text-sm text-gray-900 font-medium">{result.target_ip || '-'}</td>
                                <td className="px-6 py-4 text-sm text-gray-500">{result.target_domain || '-'}</td>
                                <td className="px-6 py-4 text-sm text-gray-900 font-bold">{result.port}</td>
                                <td className="px-6 py-4 text-sm text-gray-600">{result.service}</td>
                                <td className="px-6 py-4">
                                  <span className="px-2 py-0.5 rounded-md text-[10px] font-black border uppercase bg-green-50 text-green-700 border-green-100">
                                    {result.engine}
                                  </span>
                                </td>
                                <td className="px-6 py-4 text-xs text-gray-400 font-mono truncate max-w-[200px]" title={result.version_info}>
                                  {result.version_info || '-'}
                                </td>
                              </tr>
                            );
                          })}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Table 2: Unsupported Services */}
            {activeTab === 'unsupported' && (
              <Card className="border-l-4 border-gray-400">
                <CardHeader className="border-b bg-gray-50/50">
                  <CardTitle className="text-lg">Unsupported Services</CardTitle>
                  <p className="text-xs text-gray-500 italic mt-1">These services were detected but are not yet supported for deep compliance scanning.</p>
                </CardHeader>
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase">Target</th>
                          <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase">Port</th>
                          <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase">Service</th>
                          <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase">Status</th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-gray-100">
                        {discoveryResults.filter(r => r.engine === 'unsupported' && (r.state === 'open' || r.state === 'open|filtered')).map((result, idx) => (
                          <tr key={idx}>
                            <td className="px-6 py-4 text-sm text-gray-900 font-medium">{result.target_ip || result.target_domain}</td>
                            <td className="px-6 py-4 text-sm text-gray-500">{result.port}</td>
                            <td className="px-6 py-4 text-sm text-gray-500">{result.service}</td>
                            <td className="px-6 py-4 text-xs text-gray-400 italic">No scanner implemented</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Table 3: Filtered Ports */}
            {activeTab === 'filtered' && (
              <Card className="border-l-4 border-amber-400">
                <CardHeader className="border-b bg-gray-50/50">
                  <CardTitle className="text-lg">Filtered Ports</CardTitle>
                  <p className="text-xs text-gray-500 italic mt-1">These ports are blocked by a firewall. Direct auditing is restricted.</p>
                </CardHeader>
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase">Target</th>
                          <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase">Port</th>
                          <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase">Service</th>
                          <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase">State</th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-gray-100">
                        {discoveryResults.filter(r => r.state === 'filtered').map((result, idx) => (
                          <tr key={idx}>
                            <td className="px-6 py-4 text-sm text-gray-900 font-medium">{result.target_ip || result.target_domain}</td>
                            <td className="px-6 py-4 text-sm text-gray-500">{result.port}</td>
                            <td className="px-6 py-4 text-sm text-gray-500">{result.service}</td>
                            <td className="px-6 py-4">
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-100 text-amber-700 uppercase border border-amber-200">Filtered</span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Table 4: Inactive IPs */}
            {activeTab === 'inactive' && (
              <Card className="border-l-4 border-red-300">
                <CardHeader className="border-b bg-gray-50/50">
                  <CardTitle className="text-lg">Inactive / No Services</CardTitle>
                  <p className="text-xs text-gray-500 italic mt-1">These targets responded to probes but have no detectable services.</p>
                </CardHeader>
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200">
                      <thead className="bg-gray-50">
                        <tr>
                          <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase">Target</th>
                          <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase">Result</th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-gray-100">
                        {discoveryResults.filter(r => r.state === 'no_ports' || (r.port === 0 && r.service === 'none')).map((result, idx) => (
                          <tr key={idx}>
                            <td className="px-6 py-4 text-sm text-gray-900 font-medium">{result.target_ip || result.target_domain}</td>
                            <td className="px-6 py-4 text-sm text-gray-400 italic uppercase font-bold tracking-tighter">No Services Found</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </Card>
            )}

            <Card>
              <CardHeader className="border-b bg-gray-50/50 flex justify-between items-center">
                <CardTitle className="text-lg flex items-center gap-2">
                  <CalendarIcon className="w-5 h-5 text-indigo-600" />
                  Execution Timing
                </CardTitle>
                <div className="px-3 py-1 bg-green-100 text-green-700 text-[10px] font-bold rounded-full border border-green-200">
                  {discoveryResults.length} SERVICES DETECTED
                </div>
              </CardHeader>
              <CardContent className="p-6 space-y-8">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {frequencies.map(f => (
                    <div key={f.id} onClick={() => setScheduleType(f.id)} className={`cursor-pointer p-4 rounded-xl border-2 transition-all text-center ${scheduleType === f.id ? 'border-indigo-500 bg-indigo-50' : 'border-gray-100 bg-white hover:border-gray-200'}`}>
                      <p className={`font-bold text-sm ${scheduleType === f.id ? 'text-indigo-700' : 'text-gray-900'}`}>{f.label}</p>
                      <p className="text-[10px] text-gray-500 mt-1">{f.description}</p>
                    </div>
                  ))}
                </div>

                <div className="bg-gray-50 rounded-xl p-6 border border-gray-100 grid grid-cols-1 md:grid-cols-3 gap-6 items-end">
                  {scheduleType === 'once' && (
                    <Input label="Execution Date" type="date" value={date} min={new Date().toISOString().split('T')[0]} onChange={(e) => setDate(e.target.value)} />
                  )}
                  {scheduleType === 'weekly' && (
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">On Day</label>
                      <select value={dayOfWeek} onChange={(e) => setDayOfWeek(e.target.value)} className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm">
                        {daysOfWeek.map(d => <option key={d.value} value={d.value}>{d.label}</option>)}
                      </select>
                    </div>
                  )}
                  {scheduleType === 'monthly' && (
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Day of Month</label>
                      <select value={dayOfMonth} onChange={(e) => setDayOfMonth(e.target.value)} className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm">
                        {Array.from({length: 28}, (_, i) => i+1).map(d => <option key={d} value={d}>{d}</option>)}
                      </select>
                    </div>
                  )}
                  <Input label="Start Time" type="time" value={time} onChange={(e) => setTime(e.target.value)} />
                  
                  <div className="flex flex-col justify-center h-[38px] bg-white px-4 rounded-lg border border-gray-200">
                    <p className="text-[10px] text-gray-400 font-bold uppercase tracking-tighter">Cron Preview</p>
                    <p className="text-xs font-mono text-indigo-600 font-bold">{cronExpression}</p>
                  </div>
                </div>

                <div className="bg-blue-50 border border-blue-100 p-4 rounded-lg flex items-start gap-3">
                  <InformationCircleIcon className="w-5 h-5 text-blue-600 mt-0.5" />
                  <div>
                    <p className="text-sm font-bold text-blue-900 uppercase tracking-tight">Intelligent Automation Enabled</p>
                    <p className="text-xs text-blue-700 mt-1">This campaign will automatically re-discover services each time it runs, ensuring new vulnerabilities are caught even if your infrastructure changes.</p>
                  </div>
                </div>

                <div className="flex justify-between items-center pt-4 border-t border-gray-100">
                  <Button type="button" variant="ghost" onClick={() => setStep('details')} className="flex items-center gap-2">
                    <ChevronLeftIcon className="w-4 h-4" /> Back
                  </Button>
                  <Button type="submit" variant="primary" disabled={saving} className="px-12">
                    {saving ? 'Saving...' : (isEditing ? 'Update Schedule' : 'Activate Schedule')}
                  </Button>
                </div>
              </CardContent>
            </Card>
          </form>
        )}
      </div>

      <Modal
        isOpen={showAccessDeniedModal}
        onClose={() => setShowAccessDeniedModal(false)}
        title="Access Denied"
      >
        <div className="text-sm text-gray-500">
          {error}
        </div>
      </Modal>
    </div>
  );
}
