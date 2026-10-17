import React, { useState, useEffect, useMemo } from 'react';
import { 
  PlusIcon,
  CheckIcon,
  XIcon,
  PencilIcon,
  TrashIcon,
  ClipboardListIcon,
  InformationCircleIcon,
  BeakerIcon,
  TerminalIcon,
  ArrowRightIcon,
  DatabaseIcon
} from '@heroicons/react/outline';
import api, { listDynamicChecks, createDynamicCheck, updateDynamicCheck, deleteDynamicCheck, validateCustomRegex } from '../api/api';
import toast from 'react-hot-toast';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/Card';
import Button from '../components/ui/Button';
import Spinner from '../components/ui/Spinner';

export default function CustomChecks() {
  const [loading, setLoading] = useState(true);
  const [dynamicChecks, setDynamicChecks] = useState([]);
  const [isAddingCheck, setIsAddingCheck] = useState(false);
  const [editingCheck, setEditingCheck] = useState(null);
  const [wizardStep, setWizardStep] = useState(1);
  const [checkForm, setCheckForm] = useState({
    engine: 'web',
    tool_name: 'nmap',
    check_name: '',
    command_template: '',
    success_criteria: '',
    severity: 'INFO',
    cvss_score: 0.0,
    timeout: 300,
    remediation_text: ''
  });

  const [validation, setValidation] = useState({
    command: { valid: true, error: '' },
    regex: { valid: true, error: '', matches: false }
  });

  // Predefined samples for regex testing
  const SAMPLES = {
    nmap: "Starting Nmap 7.94\nNmap scan report for target\nPORT   STATE SERVICE\n80/tcp open  http\n443/tcp open  https\n\nNmap done: 1 IP address scanned",
    curl: "HTTP/1.1 200 OK\nServer: nginx/1.21.0\nContent-Type: text/html\nStrict-Transport-Security: max-age=31536000",
    testssl: "Testing all-ciphers...\n  TLS 1.2  offered (ok)\n  TLS 1.3  offered (ok)\n  SSLv3    not offered (OK)",
    dig: ";; ANSWER SECTION:\nexample.com.  86400  IN  A  93.184.216.34\n\n;; Query time: 10 msec",
    swaks: "=== Trying mail.example.com:25...\n=== Connected to mail.example.com.\n<-  220 mail.example.com ESMTP Postfix\n -> EHLO target.com\n<-  250-mail.example.com\n<-  250-PIPELINING\n<-  250 8BITMIME"
  };

  const fetchData = async () => {
    setLoading(true);
    try {
      const data = await listDynamicChecks();
      setDynamicChecks(data || []);
    } catch (err) {
      toast.error('Failed to load custom checks');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const validateCommand = (cmd) => {
    const forbidden = [';', '&&', '||', '|', '`', '$'];
    if (forbidden.some(c => cmd.includes(c))) {
      return { valid: false, error: 'Command contains forbidden shell characters' };
    }
    if (checkForm.tool_name === 'nmap' && !cmd.includes('{domain}') && !cmd.includes('{dns_ip}')) {
      return { valid: false, error: 'Nmap command must contain {domain} or {dns_ip}' };
    }
    return { valid: true, error: '' };
  };

  const testRegex = async (regex) => {
    if (!regex) return;
    try {
      const sample = SAMPLES[checkForm.tool_name] || SAMPLES.nmap;
      const res = await validateCustomRegex(regex, sample);
      setValidation(prev => ({ 
        ...prev, 
        regex: { 
          valid: res.valid, 
          error: res.error || (res.matches ? '' : 'Regex does not match the sample output'),
          matches: res.matches 
        } 
      }));
    } catch (e) {
      setValidation(prev => ({ ...prev, regex: { valid: false, error: 'Server error during validation', matches: false } }));
    }
  };

  const canMoveToNext = useMemo(() => {
    if (wizardStep === 1) return checkForm.check_name.length > 2;
    if (wizardStep === 2) {
        const v = validateCommand(checkForm.command_template);
        return v.valid && checkForm.command_template.length > 5;
    }
    if (wizardStep === 3) return validation.regex.valid && validation.regex.matches;
    return true;
  }, [wizardStep, checkForm, validation]);

  const saveCheck = async () => {
    try {
      if (editingCheck) {
        await updateDynamicCheck(editingCheck.id, checkForm);
        toast.success('Check updated');
      } else {
        await createDynamicCheck(checkForm);
        toast.success('Check created');
      }
      setIsAddingCheck(false);
      setEditingCheck(null);
      setWizardStep(1);
      setCheckForm({
        engine: 'web',
        tool_name: 'nmap',
        check_name: '',
        command_template: '',
        success_criteria: '',
        severity: 'INFO',
        cvss_score: 0.0,
        timeout: 300,
        remediation_text: ''
      });
      fetchData();
    } catch (err) {
      toast.error('Failed to save check');
    }
  };

  const toggleCheck = async (check) => {
    try {
      await updateDynamicCheck(check.id, { is_active: !check.is_active });
      fetchData();
    } catch (err) {
      toast.error('Failed to toggle check');
    }
  };

  const removeCheck = async (id) => {
    if (!window.confirm('Delete this check?')) return;
    try {
      await deleteDynamicCheck(id);
      toast.success('Check deleted');
      fetchData();
    } catch (err) {
      toast.error('Failed to delete check');
    }
  };

  const renderCheckWizard = () => {
    return (
      <div className="bg-white border border-gray-200 rounded-2xl shadow-xl overflow-hidden mb-8 animate-slide-down">
        <div className="p-8">
          {/* Wizard Progress */}
          <div className="flex items-center justify-between mb-10 relative">
            <div className="absolute top-1/2 left-0 w-full h-0.5 bg-gray-100 -z-0"></div>
            {[1, 2, 3, 4].map(step => (
              <div key={step} className={`
                relative z-10 w-10 h-10 rounded-full flex items-center justify-center text-sm font-black transition-all
                ${wizardStep >= step ? 'bg-primary-600 text-white ring-4 ring-primary-50' : 'bg-white border-2 border-gray-200 text-gray-400'}
              `}>
                {step}
              </div>
            ))}
          </div>

          <h3 className="text-xl font-black text-gray-900 mb-8 flex items-center gap-3">
             <div className="p-2 bg-primary-100 rounded-lg text-primary-600">
                <ClipboardListIcon className="w-5 h-5" />
             </div>
             {editingCheck ? 'Refine Custom Check' : 'Create New Security Standard'}
          </h3>

          <div className="grid grid-cols-1 gap-8">
            {/* STEP 1: Core Identity */}
            {wizardStep === 1 && (
              <div className="space-y-6 animate-fade-in">
                 <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-2">
                        <label className="text-[10px] font-black text-gray-400 uppercase tracking-widest">Scanning Engine</label>
                        <select 
                            className="w-full text-sm border-2 border-gray-100 rounded-xl px-4 py-3 outline-none focus:border-primary-500 transition-colors bg-gray-50/50"
                            value={checkForm.engine}
                            onChange={(e) => setCheckForm({...checkForm, engine: e.target.value})}
                        >
                            <option value="web">Web Security</option>
                            <option value="dns">DNS Records</option>
                            <option value="email">Email Compliance</option>
                            <option value="network">Network Infrastructure</option>
                            <option value="ssh">SSH Hardening</option>
                            <option value="ftp">FTP Security</option>
                        </select>
                    </div>
                    <div className="space-y-2">
                        <label className="text-[10px] font-black text-gray-400 uppercase tracking-widest">Base Tool</label>
                        <select 
                            className="w-full text-sm border-2 border-gray-100 rounded-xl px-4 py-3 outline-none focus:border-primary-500 transition-colors bg-gray-50/50"
                            value={checkForm.tool_name}
                            onChange={(e) => setCheckForm({...checkForm, tool_name: e.target.value})}
                        >
                            <option value="nmap">Nmap (Network/Port)</option>
                            <option value="curl">Curl (Web/Headers)</option>
                            <option value="testssl">TestSSL (Encryption)</option>
                            <option value="dig">Dig (DNS Queries)</option>
                            <option value="swaks">Swaks (Email SMTP)</option>
                        </select>
                    </div>
                 </div>
                 <div className="space-y-2">
                    <label className="text-[10px] font-black text-gray-400 uppercase tracking-widest">Check Identity Name</label>
                    <input 
                        type="text" 
                        placeholder="e.g. HSTS Header Missing" 
                        className="w-full text-lg font-bold border-2 border-gray-100 rounded-xl px-4 py-3 outline-none focus:border-primary-500 transition-colors"
                        value={checkForm.check_name}
                        onChange={(e) => setCheckForm({...checkForm, check_name: e.target.value})}
                    />
                    <p className="text-[10px] text-gray-400 font-medium italic">Check ID will be auto-generated based on this name.</p>
                 </div>
              </div>
            )}

            {/* STEP 2: Command Construction */}
            {wizardStep === 2 && (
              <div className="space-y-6 animate-fade-in">
                 <div className="bg-gray-900 rounded-xl p-6 text-white overflow-hidden shadow-2xl">
                    <div className="flex items-center gap-2 mb-4">
                        <div className="w-3 h-3 rounded-full bg-red-500"></div>
                        <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                        <div className="w-3 h-3 rounded-full bg-green-500"></div>
                        <span className="text-[10px] font-mono text-gray-500 ml-2">command_builder.sh</span>
                    </div>
                    <textarea 
                        rows="3" 
                        className="w-full bg-transparent border-none outline-none font-mono text-primary-400 resize-none"
                        placeholder={`${checkForm.tool_name} -p {port} {domain}`}
                        value={checkForm.command_template}
                        onChange={(e) => {
                            const val = e.target.value;
                            setCheckForm({...checkForm, command_template: val});
                            const v = validateCommand(val);
                            setValidation(prev => ({ ...prev, command: v }));
                        }}
                    />
                 </div>
                 {!validation.command.valid && (
                    <div className="p-3 bg-red-50 border border-red-100 rounded-lg text-red-600 text-xs font-bold flex items-center gap-2">
                        <XIcon className="w-4 h-4" />
                        {validation.command.error}
                    </div>
                 )}
                 <div className="grid grid-cols-3 gap-4">
                    {['{domain}', '{port}', '{dns_ip}'].map(tag => (
                        <button 
                            key={tag}
                            className="py-2 px-3 bg-white border border-gray-200 rounded-lg text-[10px] font-black text-gray-500 hover:border-primary-500 hover:text-primary-600 transition-all"
                            onClick={() => setCheckForm(f => ({...f, command_template: f.command_template + tag}))}
                        >
                            Insert {tag}
                        </button>
                    ))}
                 </div>

                 <div className="space-y-2 pt-4 border-t border-gray-50">
                    <label className="text-[10px] font-black text-gray-400 uppercase tracking-widest text-left block">Execution Timeout (Seconds)</label>
                    <div className="flex items-center gap-4">
                        <input 
                            type="range" min="5" max="1800" step="5"
                            className="flex-1 accent-primary-600"
                            value={checkForm.timeout}
                            onChange={(e) => setCheckForm({...checkForm, timeout: parseInt(e.target.value)})}
                        />
                        <span className="w-20 text-center font-mono font-black text-primary-700 bg-primary-50 px-3 py-1.5 rounded-lg border border-primary-100">
                            {checkForm.timeout}s
                        </span>
                    </div>
                    <p className="text-[9px] text-gray-400">Maximum time allowed for this command to run before it is terminated.</p>
                 </div>
              </div>
            )}

            {/* STEP 3: Logic & Validation */}
            {wizardStep === 3 && (
              <div className="space-y-6 animate-fade-in">
                 <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                    <div className="space-y-4">
                        <label className="text-[10px] font-black text-gray-400 uppercase tracking-widest">Success Criteria (Regex)</label>
                        <input 
                            type="text" 
                            placeholder="e.g. 200 OK|301 Moved" 
                            className="w-full font-mono text-sm border-2 border-gray-100 rounded-xl px-4 py-3 outline-none focus:border-primary-500 transition-colors"
                            value={checkForm.success_criteria}
                            onChange={(e) => {
                                setCheckForm({...checkForm, success_criteria: e.target.value});
                            }}
                            onBlur={(e) => testRegex(e.target.value)}
                        />
                        {validation.regex.error && (
                            <p className="text-[10px] text-red-500 font-bold">{validation.regex.error}</p>
                        )}
                        <Button 
                            variant="outline" size="sm" className="w-full text-[10px]"
                            onClick={() => testRegex(checkForm.success_criteria)}
                        >
                            <BeakerIcon className="w-3.5 h-3.5 mr-2" />
                            Run Regex Validation
                        </Button>
                    </div>
                    <div className="space-y-2">
                        <label className="text-[10px] font-black text-gray-400 uppercase tracking-widest">Test Against Sample Output</label>
                        <div className="bg-gray-50 border border-gray-200 rounded-xl p-4 h-40 overflow-y-auto font-mono text-[10px] text-gray-600 leading-relaxed">
                            <div className="flex justify-between items-center mb-2 border-b border-gray-200 pb-2">
                                <span className="font-black text-gray-400">SAMPLE OUTPUT ({checkForm.tool_name.toUpperCase()})</span>
                                <span className={`px-1.5 py-0.5 rounded text-[8px] font-black ${validation.regex.matches ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
                                    {validation.regex.matches ? 'MATCH FOUND' : 'NO MATCH'}
                                </span>
                            </div>
                            <pre className="whitespace-pre-wrap">
                                {SAMPLES[checkForm.tool_name] || SAMPLES.nmap}
                            </pre>
                        </div>
                    </div>
                 </div>
              </div>
            )}

            {/* STEP 4: Risk & Remediation */}
            {wizardStep === 4 && (
              <div className="space-y-6 animate-fade-in">
                 <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-2">
                        <label className="text-[10px] font-black text-gray-400 uppercase tracking-widest">Severity Classification</label>
                        <select 
                            className="w-full text-sm border-2 border-gray-100 rounded-xl px-4 py-3 outline-none focus:border-primary-500 transition-colors"
                            value={checkForm.severity}
                            onChange={(e) => setCheckForm({...checkForm, severity: e.target.value})}
                        >
                            <option value="CRITICAL">CRITICAL</option>
                            <option value="HIGH">HIGH</option>
                            <option value="MEDIUM">MEDIUM</option>
                            <option value="LOW">LOW</option>
                            <option value="INFO">INFO</option>
                        </select>
                    </div>
                    <div className="space-y-2">
                        <label className="text-[10px] font-black text-gray-400 uppercase tracking-widest">CVSS Base Score (0-10)</label>
                        <input 
                            type="number" step="0.1" min="0" max="10"
                            className="w-full text-sm border-2 border-gray-100 rounded-xl px-4 py-3 outline-none focus:border-primary-500 transition-colors"
                            value={checkForm.cvss_score}
                            onChange={(e) => setCheckForm({...checkForm, cvss_score: parseFloat(e.target.value)})}
                        />
                    </div>
                 </div>
                 <div className="space-y-2">
                    <label className="text-[10px] font-black text-gray-400 uppercase tracking-widest">Remediation Guidance</label>
                    <textarea 
                        rows="4" 
                        className="w-full text-sm border-2 border-gray-100 rounded-xl px-4 py-3 outline-none focus:border-primary-500 transition-colors"
                        placeholder="Step-by-step instructions to fix this vulnerability..."
                        value={checkForm.remediation_text}
                        onChange={(e) => setCheckForm({...checkForm, remediation_text: e.target.value})}
                    />
                 </div>
              </div>
            )}
          </div>
        </div>

        <div className="px-8 py-6 bg-gray-50 border-t border-gray-100 flex justify-between items-center">
          <Button 
              variant="ghost" 
              onClick={() => {
                  if (wizardStep === 1) {
                      setIsAddingCheck(false);
                      setEditingCheck(null);
                  } else {
                      setWizardStep(wizardStep - 1);
                  }
              }}
          >
              {wizardStep === 1 ? 'Cancel Operation' : 'Previous Step'}
          </Button>
          
          <div className="flex gap-3">
              {wizardStep < 4 ? (
                  <Button 
                      className="bg-primary-600 text-white px-8 h-12 rounded-xl shadow-lg shadow-primary-500/20" 
                      disabled={!canMoveToNext}
                      onClick={() => setWizardStep(wizardStep + 1)}
                  >
                      Proceed to next &rarr;
                  </Button>
              ) : (
                  <Button 
                      className="bg-green-600 hover:bg-green-700 text-white px-10 h-12 rounded-xl shadow-lg shadow-green-500/20" 
                      onClick={saveCheck}
                  >
                      <CheckIcon className="w-5 h-5 mr-2" />
                      Commit Standard
                  </Button>
              )}
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="max-w-7xl mx-auto p-6 space-y-8 animate-fade-in">
      {/* Header */}
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-black text-gray-900 tracking-tight">Compliance Standards</h1>
          <p className="text-gray-500 mt-1 font-medium italic">Architect and manage custom security assertions for the scanning engines</p>
        </div>
        <Button 
          size="lg" 
          className="bg-primary-600 hover:bg-primary-700 text-white shadow-xl shadow-primary-500/20 rounded-xl"
          onClick={() => {
            setEditingCheck(null);
            setWizardStep(1);
            setCheckForm({
              engine: 'web',
              tool_name: 'nmap',
              check_name: '',
              command_template: '',
              success_criteria: '',
              severity: 'INFO',
              cvss_score: 0.0,
              timeout: 300,
              remediation_text: ''
            });
            setIsAddingCheck(true);
          }}
        >
          <PlusIcon className="w-5 h-5 mr-2" />
          New Assertion
        </Button>
      </div>

      {(isAddingCheck || editingCheck) && renderCheckWizard()}

      {/* Main List */}
      <Card className="shadow-2xl border-gray-100 overflow-hidden rounded-2xl ring-1 ring-black/5">
        <CardHeader className="bg-gray-50/50 border-b border-gray-100 flex flex-row items-center justify-between">
          <CardTitle className="text-sm font-black flex items-center gap-2 uppercase tracking-widest text-gray-500">
            <ClipboardListIcon className="w-4 h-4 text-primary-500" />
            Configured Standards ({dynamicChecks.length})
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-100">
              <thead className="bg-white">
                <tr>
                  <th className="px-6 py-4 text-left text-[10px] font-black text-gray-400 uppercase tracking-widest">State</th>
                  <th className="px-6 py-4 text-left text-[10px] font-black text-gray-400 uppercase tracking-widest">Engine / Tool</th>
                  <th className="px-6 py-4 text-left text-[10px] font-black text-gray-400 uppercase tracking-widest">Standard ID</th>
                  <th className="px-6 py-4 text-left text-[10px] font-black text-gray-400 uppercase tracking-widest">Requirement Name</th>
                  <th className="px-6 py-4 text-left text-[10px] font-black text-gray-400 uppercase tracking-widest">Severity</th>
                  <th className="px-6 py-4 text-right text-[10px] font-black text-gray-400 uppercase tracking-widest">Actions</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-50">
                {dynamicChecks.map((check) => (
                  <tr key={check.id} className="hover:bg-gray-50/50 transition-colors group">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <button 
                        onClick={() => toggleCheck(check)}
                        className={`w-10 h-5 rounded-full transition-all relative ${check.is_active ? 'bg-primary-600 shadow-inner' : 'bg-gray-200'}`}
                      >
                        <span className={`absolute top-1 w-3 h-3 rounded-full bg-white transition-all shadow-sm ${check.is_active ? 'left-6' : 'left-1'}`}></span>
                      </button>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex flex-col">
                        <span className={`px-2 py-0.5 rounded text-[9px] font-black uppercase inline-block w-fit ${
                          check.engine === 'web' ? 'bg-blue-50 text-blue-600 border border-blue-100' : 'bg-green-50 text-green-600 border border-green-100'
                        }`}>
                          {check.engine}
                        </span>
                        <span className="text-[10px] text-gray-400 font-bold mt-1 ml-1">{check.tool_name}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-[10px] font-black font-mono text-gray-400 group-hover:text-primary-600 transition-colors">
                      {check.check_id_string}
                    </td>
                    <td className="px-6 py-4">
                      <p className="text-xs font-black text-gray-900 leading-tight">{check.check_name}</p>
                      <p className="text-[9px] text-gray-400 mt-0.5 font-medium truncate max-w-[200px] italic">{check.command_template}</p>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                       <span className={`px-2 py-1 rounded-lg text-[9px] font-black uppercase tracking-tighter ${
                          check.severity === 'CRITICAL' ? 'bg-red-100 text-red-700' :
                          check.severity === 'HIGH' ? 'bg-red-50 text-red-600' :
                          check.severity === 'MEDIUM' ? 'bg-orange-50 text-orange-600' :
                          'bg-primary-50 text-primary-600'
                        }`}>
                          {check.severity}
                        </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-xs font-medium">
                      <div className="flex justify-end gap-3">
                        <button 
                          onClick={() => {
                            setEditingCheck(check);
                            setCheckForm({...check});
                            setWizardStep(1);
                            setIsAddingCheck(false);
                          }}
                          className="text-gray-300 hover:text-primary-600 transition-colors p-1"
                          title="Edit Standard"
                        >
                          <PencilIcon className="w-5 h-5" />
                        </button>
                        <button 
                          onClick={() => removeCheck(check.id)}
                          className="text-gray-300 hover:text-rose-600 transition-colors p-1"
                          title="Delete Standard"
                        >
                          <TrashIcon className="w-5 h-5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {dynamicChecks.length === 0 && !loading && (
                  <tr>
                    <td colSpan="6" className="px-6 py-20 text-center">
                      <DatabaseIcon className="w-12 h-12 text-gray-100 mx-auto mb-4" />
                      <p className="text-gray-400 font-black uppercase tracking-widest text-xs">No Standards Defined</p>
                      <p className="text-gray-300 text-[10px] mt-1 font-medium">Click "New Assertion" to start architecting security checks.</p>
                    </td>
                  </tr>
                )}
                {loading && (
                  <tr>
                    <td colSpan="6" className="px-6 py-12 text-center">
                      <Spinner size="md" className="mx-auto" />
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
