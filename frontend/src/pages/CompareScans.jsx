// src/pages/CompareScans.jsx
import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ArrowLeftIcon,
  ScaleIcon,
  ChevronDownIcon,
  CheckCircleIcon,
  XCircleIcon,
  MinusCircleIcon,
  TrendingUpIcon,
  TrendingDownIcon,
  ShieldCheckIcon,
  ViewGridIcon,
  DocumentDuplicateIcon,
  DownloadIcon
} from '@heroicons/react/outline';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Cell
} from 'recharts';
import { listScanGroups, getGroupScans, compareReports, compareCampaigns, downloadComparisonReport } from '../api/api';
import { Card, CardHeader, CardTitle, CardContent } from "../components/ui/Card";
import Button from '../components/ui/Button';
import Badge from '../components/ui/Badge';
import Spinner from '../components/ui/Spinner';
import { cn } from '../utils/cn';
import toast from 'react-hot-toast';
import ScanTypeBadge from '../components/ScanTypeBadge';

function getDifferenceColor(diff) {
  if (diff > 0) return 'text-emerald-600';
  if (diff < 0) return 'text-rose-600';
  return 'text-gray-600';
}

function getDifferenceIcon(diff) {
  if (diff > 0) return <TrendingUpIcon className="w-5 h-5 text-emerald-600" />;
  if (diff < 0) return <TrendingDownIcon className="w-5 h-5 text-rose-600" />;
  return <MinusCircleIcon className="w-5 h-5 text-gray-600" />;
}

export default function CompareScans() {
  const navigate = useNavigate();

  const [campaigns, setCampaigns] = useState([]);
  const [camp1Id, setCamp1Id] = useState('');
  const [camp2Id, setCamp2Id] = useState('');
  
  const [compareMode, setCompareMode] = useState('full'); // 'full' or 'individual'
  
  const [scans1, setScans1] = useState([]);
  const [scans2, setScans2] = useState([]);
  const [scan1Id, setScan1Id] = useState('');
  const [scan2Id, setScan2Id] = useState('');

  const [comparison, setComparison] = useState(null);
  const [loading, setLoading] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [loadingScans1, setLoadingScans1] = useState(false);
  const [loadingScans2, setLoadingScans2] = useState(false);
  const [error, setError] = useState('');

  // Get selected scan details for filtering
  const selectedScan1 = scans1.find(s => String(s.id) === String(scan1Id));
  const scan1Type = selectedScan1?.scan_type;
  const scan1Domain = selectedScan1?.domain;

  const filteredScans2 = scan1Id 
    ? scans2.filter(s => s.scan_type === scan1Type && s.domain === scan1Domain)
    : scans2;

  // Reset scan2 if it's no longer in filtered list
  useEffect(() => {
    if (scan2Id && !filteredScans2.some(s => String(s.id) === String(scan2Id))) {
      setScan2Id('');
    }
  }, [filteredScans2, scan2Id]);

  useEffect(() => {
    fetchCampaigns();
  }, []);

  const handleDownload = async () => {
    if (!scan1Id || !scan2Id) return;
    setDownloading(true);
    try {
      await downloadComparisonReport(scan1Id, scan2Id);
      toast.success('Report downloaded');
    } catch (err) {
      console.error("Download failed:", err);
      toast.error('Failed to generate PDF');
    } finally {
      setDownloading(false);
    }
  };

  const fetchCampaigns = async () => {
    try {
      const res = await listScanGroups();
      const data = res?.data || res || [];
      setCampaigns(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error("Failed to load campaigns:", err);
      toast.error('Failed to load campaigns');
    }
  };

  const fetchScansForCamp = useCallback(async (campId, setter, loadingSetter) => {
    if (!campId) {
        setter([]);
        return;
    }
    loadingSetter(true);
    try {
      const res = await getGroupScans(campId);
      const data = res?.data || res || [];
      const completed = Array.isArray(data) ? data.filter(s => s.status === 'COMPLETED') : [];
      setter(completed);
    } catch (err) {
      console.error(`Failed to load scans for campaign ${campId}:`, err);
      toast.error('Failed to load scans');
    } finally {
      loadingSetter(false);
    }
  }, []);

  useEffect(() => {
    if (compareMode === 'individual' && camp1Id) {
        fetchScansForCamp(camp1Id, setScans1, setLoadingScans1);
    }
  }, [camp1Id, compareMode, fetchScansForCamp]);

  useEffect(() => {
    if (compareMode === 'individual' && camp2Id) {
        fetchScansForCamp(camp2Id, setScans2, setLoadingScans2);
    }
  }, [camp2Id, compareMode, fetchScansForCamp]);

  const handleCompare = async () => {
    setError('');
    if (!camp1Id || !camp2Id) {
      toast.error('Please select two campaigns');
      return;
    }

    if (compareMode === 'individual' && (!scan1Id || !scan2Id)) {
      toast.error('Please select individual scans to compare');
      return;
    }

    setLoading(true);
    setComparison(null);

    try {
      let res;
      if (compareMode === 'full') {
        res = await compareCampaigns(camp1Id, camp2Id);
      } else {
        res = await compareReports(scan1Id, scan2Id);
      }
      const data = res?.data || res;
      if (!data) throw new Error("No comparison data received");
      
      setComparison(data);
      toast.success('Comparison loaded');
    } catch (err) {
      console.error("Comparison failed:", err);
      setError(err.message || 'Failed to compare');
      toast.error(err.message || 'Failed to compare');
    } finally {
      setLoading(false);
    }
  };

  // Prepare chart data
  const chartData = comparison ? (
    comparison.is_campaign_comparison ? [
      { name: 'Improved', count: comparison.improved_scans?.length || 0, color: '#10b981' },
      { name: 'Worsened', count: comparison.worsened_scans?.length || 0, color: '#f43f5e' },
      { name: 'Unchanged', count: comparison.unchanged_scans?.length || 0, color: '#6b7280' },
    ] : [
      { name: 'Improved', count: comparison.improved_checks?.length || 0, color: '#10b981' },
      { name: 'Worsened', count: comparison.worsened_checks?.length || 0, color: '#f43f5e' },
      { name: 'Unchanged', count: comparison.unchanged_checks?.length || 0, color: '#6b7280' },
    ]
  ) : [];

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate('/reports')}
              className="p-2 hover:bg-gray-200 rounded-full transition-colors"
            >
              <ArrowLeftIcon className="w-6 h-6 text-gray-600" />
            </button>
            <div>
              <h1 className="text-3xl font-black text-gray-900 tracking-tight">Comparison Engine</h1>
              <p className="text-gray-500 font-medium">Analyze security posture changes over time</p>
            </div>
          </div>
        </div>

        {/* Selection Interface */}
        <Card className="shadow-sm border-gray-200">
          <CardContent className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <label className="text-xs font-black text-gray-400 uppercase tracking-widest">Baseline Selection</label>
                <select
                  value={camp1Id}
                  onChange={(e) => { setCamp1Id(e.target.value); setScan1Id(''); }}
                  className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-lg focus:ring-2 focus:ring-primary-500 transition-all font-bold text-gray-700"
                >
                  <option value="">Select Campaign 1...</option>
                  {campaigns.map(c => (
                    <option key={c.id} value={c.id}>{c.name} ({c.avg_compliance}%)</option>
                  ))}
                </select>

                {compareMode === 'individual' && camp1Id && (
                  <div className="relative">
                    <select
                        value={scan1Id}
                        onChange={(e) => setScan1Id(e.target.value)}
                        className="w-full px-4 py-3 bg-white border border-gray-200 rounded-lg focus:ring-2 focus:ring-primary-500 transition-all text-sm appearance-none"
                        disabled={loadingScans1}
                    >
                        <option value="">{loadingScans1 ? 'Loading scans...' : 'Select Scan from Campaign 1...'}</option>
                        {scans1.map(s => (
                        <option key={s.id} value={s.id}>{s.domain} - {s.scan_type} ({s.compliance_percent}%)</option>
                        ))}
                    </select>
                    {loadingScans1 && (
                        <div className="absolute right-3 top-3">
                            <Spinner size="xs" />
                        </div>
                    )}
                  </div>
                )}
              </div>

              <div className="space-y-4">
                <label className="text-xs font-black text-gray-400 uppercase tracking-widest">Comparison Target</label>
                <select
                  value={camp2Id}
                  onChange={(e) => { setCamp2Id(e.target.value); setScan2Id(''); }}
                  className="w-full px-4 py-3 bg-gray-50 border border-gray-200 rounded-lg focus:ring-2 focus:ring-primary-500 transition-all font-bold text-gray-700"
                >
                  <option value="">Select Campaign 2...</option>
                  {campaigns.map(c => (
                    <option key={c.id} value={c.id}>{c.name} ({c.avg_compliance}%)</option>
                  ))}
                </select>

                {compareMode === 'individual' && camp2Id && (
                  <div className="relative">
                    <select
                        value={scan2Id}
                        onChange={(e) => setScan2Id(e.target.value)}
                        className="w-full px-4 py-3 bg-white border border-gray-200 rounded-lg focus:ring-2 focus:ring-primary-500 transition-all text-sm appearance-none"
                        disabled={loadingScans2 || !scan1Id}
                    >
                        <option value="">{!scan1Id ? 'Select Baseline Scan First' : loadingScans2 ? 'Loading scans...' : `Select same target (${scan1Domain}) from Campaign 2...`}</option>
                        {filteredScans2.map(s => (
                        <option key={s.id} value={s.id}>{s.domain} - {s.scan_type} ({s.compliance_percent}%)</option>
                        ))}
                    </select>
                    {loadingScans2 && (
                        <div className="absolute right-3 top-3">
                            <Spinner size="xs" />
                        </div>
                    )}
                    {scan1Id && filteredScans2.length === 0 && !loadingScans2 && (
                      <p className="text-[10px] text-rose-500 font-bold mt-1 uppercase tracking-tighter">No matching {scan1Type} scan for {scan1Domain} found</p>
                    )}
                  </div>
                )}
              </div>
            </div>

            <div className="mt-8 flex flex-col md:flex-row items-center justify-between gap-6 pt-6 border-t border-gray-100">
              <div className="flex bg-gray-100 p-1 rounded-xl w-full md:w-auto">
                <button
                  onClick={() => { setCompareMode('full'); setComparison(null); }}
                  className={cn(
                    "flex-1 md:flex-none px-6 py-2 rounded-lg text-sm font-bold transition-all flex items-center justify-center gap-2",
                    compareMode === 'full' ? "bg-white text-primary-600 shadow-sm" : "text-gray-500 hover:text-gray-700"
                  )}
                >
                  <ViewGridIcon className="w-4 h-4" />
                  Full Campaign
                </button>
                <button
                  onClick={() => { setCompareMode('individual'); setComparison(null); }}
                  className={cn(
                    "flex-1 md:flex-none px-6 py-2 rounded-lg text-sm font-bold transition-all flex items-center justify-center gap-2",
                    compareMode === 'individual' ? "bg-white text-primary-600 shadow-sm" : "text-gray-500 hover:text-gray-700"
                  )}
                >
                  <DocumentDuplicateIcon className="w-4 h-4" />
                  Selected Scans
                </button>
              </div>

              <Button
                variant="primary"
                size="lg"
                onClick={handleCompare}
                disabled={loading || !camp1Id || !camp2Id || (compareMode === 'individual' && (!scan1Id || !scan2Id))}
                className="w-full md:w-auto px-12 rounded-xl shadow-lg shadow-primary-100"
              >
                {loading ? <Spinner size="sm" /> : <><ScaleIcon className="w-5 h-5 mr-2" /> Compare Now</>}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Results Section */}
        {comparison && (
          <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
            {/* Download Button Row */}
            {!comparison.is_campaign_comparison && (
              <div className="flex justify-end">
                <Button
                  variant="outline"
                  onClick={handleDownload}
                  disabled={downloading}
                  className="bg-white border-primary-200 text-primary-600 hover:bg-primary-50 shadow-sm"
                >
                  {downloading ? <Spinner size="sm" /> : <><DownloadIcon className="w-4 h-4 mr-2" /> Download Comparison PDF</>}
                </Button>
              </div>
            )}
            
            {/* Top Stats */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <Card className="bg-white border-l-4 border-l-primary-500">
                <CardContent className="p-6">
                  <p className="text-[10px] font-black text-gray-400 uppercase tracking-widest mb-1">Baseline</p>
                  <h4 className="text-sm font-bold text-gray-700 truncate mb-2">{comparison.is_campaign_comparison ? comparison.group1_name : comparison.scan1_domain}</h4>
                  <p className="text-3xl font-black text-gray-900">{comparison.is_campaign_comparison ? comparison.group1_avg : comparison.scan1_percent}%</p>
                </CardContent>
              </Card>

              <Card className={cn("bg-white border-l-4", (comparison.difference || 0) >= 0 ? "border-l-green-500" : "border-l-red-500")}>
                <CardContent className="p-6">
                  <p className="text-[10px] font-black text-gray-400 uppercase tracking-widest mb-1">Delta</p>
                  <div className="flex items-center gap-2">
                    {getDifferenceIcon(comparison.difference)}
                    <span className={cn("text-3xl font-black", getDifferenceColor(comparison.difference))}>
                      {(comparison.difference || 0) > 0 ? '+' : ''}{comparison.difference || 0}%
                    </span>
                  </div>
                  <p className="text-xs font-bold text-gray-500 mt-2 uppercase tracking-tight">Global Compliance Change</p>
                </CardContent>
              </Card>

              <Card className="bg-white border-l-4 border-l-primary-500">
                <CardContent className="p-6">
                  <p className="text-[10px] font-black text-gray-400 uppercase tracking-widest mb-1">Target</p>
                  <h4 className="text-sm font-bold text-gray-700 truncate mb-2">{comparison.is_campaign_comparison ? comparison.group2_name : comparison.scan2_domain}</h4>
                  <p className="text-3xl font-black text-gray-900">{comparison.is_campaign_comparison ? comparison.group2_avg : comparison.scan2_percent}%</p>
                </CardContent>
              </Card>
            </div>

            {/* Distribution Graph */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <Card className="lg:col-span-2 shadow-sm">
                <CardHeader>
                  <CardTitle className="text-lg">Change Distribution</CardTitle>
                </CardHeader>
                <CardContent className="h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={chartData} layout="vertical" margin={{ left: 40, right: 40 }}>
                      <CartesianGrid strokeDasharray="3 3" horizontal={false} />
                      <XAxis type="number" hide />
                      <YAxis dataKey="name" type="category" width={80} tick={{ fontSize: 12, fontWeight: 'bold' }} />
                      <Tooltip cursor={{ fill: '#f3f4f6' }} contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }} />
                      <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={32}>
                        {chartData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>

              <div className="space-y-4">
                <div className="p-4 bg-green-50 rounded-xl border border-green-100 flex items-center justify-between">
                  <div>
                    <p className="text-[10px] font-black text-green-700 uppercase">Improved</p>
                    <p className="text-2xl font-black text-green-900">{chartData[0]?.count || 0}</p>
                  </div>
                  <CheckCircleIcon className="w-10 h-10 text-green-500 opacity-20" />
                </div>
                <div className="p-4 bg-red-50 rounded-xl border border-red-100 flex items-center justify-between">
                  <div>
                    <p className="text-[10px] font-black text-red-700 uppercase">Worsened</p>
                    <p className="text-2xl font-black text-red-900">{chartData[1]?.count || 0}</p>
                  </div>
                  <XCircleIcon className="w-10 h-10 text-red-500 opacity-20" />
                </div>
                <div className="p-4 bg-gray-50 rounded-xl border border-gray-100 flex items-center justify-between">
                  <div>
                    <p className="text-[10px] font-black text-gray-700 uppercase">Unchanged</p>
                    <p className="text-2xl font-black text-gray-900">{chartData[2]?.count || 0}</p>
                  </div>
                  <MinusCircleIcon className="w-10 h-10 text-gray-500 opacity-20" />
                </div>
              </div>
            </div>

            {/* Detailed Lists */}
            {comparison.is_campaign_comparison ? (
              <div className="space-y-6">
                {(comparison.improved_scans?.length > 0) && (
                  <Card className="border border-green-100 shadow-sm overflow-hidden">
                    <div className="bg-green-50 px-6 py-3 border-b border-green-100">
                      <h3 className="text-sm font-black text-green-800 uppercase tracking-wider">Improved Matched Scans</h3>
                    </div>
                    <div className="divide-y divide-gray-100">
                      {comparison.improved_scans.map((item, i) => (
                        <div key={i} className="px-6 py-4 flex items-center justify-between hover:bg-gray-50 transition-colors">
                          <div className="flex items-center gap-3">
                            <ScanTypeBadge type={item.type} />
                            <span className="font-bold text-gray-900">{item.target}</span>
                          </div>
                          <div className="flex items-center gap-3">
                            <span className="text-xs font-bold text-gray-400">{item.pct1}%</span>
                            <ArrowLeftIcon className="w-3 h-3 text-gray-300 rotate-180" />
                            <span className="text-sm font-black text-green-600">{item.pct2}%</span>
                            <Badge variant="success" size="sm">+{item.diff}%</Badge>
                          </div>
                        </div>
                      ))}
                    </div>
                  </Card>
                )}
                {(comparison.worsened_scans?.length > 0) && (
                  <Card className="border border-red-100 shadow-sm overflow-hidden">
                    <div className="bg-red-50 px-6 py-3 border-b border-red-100">
                      <h3 className="text-sm font-black text-red-800 uppercase tracking-wider">Regressed Matched Scans</h3>
                    </div>
                    <div className="divide-y divide-gray-100">
                      {comparison.worsened_scans.map((item, i) => (
                        <div key={i} className="px-6 py-4 flex items-center justify-between hover:bg-gray-50 transition-colors">
                          <div className="flex items-center gap-3">
                            <ScanTypeBadge type={item.type} />
                            <span className="font-bold text-gray-900">{item.target}</span>
                          </div>
                          <div className="flex items-center gap-3">
                            <span className="text-xs font-bold text-gray-400">{item.pct1}%</span>
                            <ArrowLeftIcon className="w-3 h-3 text-gray-300 rotate-180" />
                            <span className="text-sm font-black text-red-600">{item.pct2}%</span>
                            <Badge variant="danger" size="sm">{item.diff}%</Badge>
                          </div>
                        </div>
                      ))}
                    </div>
                  </Card>
                )}
              </div>
            ) : (
              <div className="space-y-6">
                {(comparison.improved_checks?.length > 0) && (
                  <Card className="border border-green-100 shadow-sm overflow-hidden">
                    <div className="bg-green-50 px-6 py-3 border-b border-green-100">
                      <h3 className="text-sm font-black text-green-800 uppercase tracking-wider">Remediated Findings</h3>
                    </div>
                    <div className="divide-y divide-gray-100">
                      {comparison.improved_checks.map((check) => (
                        <div key={check.check_id} className="px-6 py-4 flex items-center justify-between hover:bg-gray-50 transition-colors">
                          <span className="font-bold text-gray-900">{check.check_name}</span>
                          <div className="flex items-center gap-3">
                            <Badge variant="danger" size="sm">{check.scan1}</Badge>
                            <ArrowLeftIcon className="w-3 h-3 text-gray-300 rotate-180" />
                            <Badge variant="success" size="sm">{check.scan2}</Badge>
                          </div>
                        </div>
                      ))}
                    </div>
                  </Card>
                )}
                {(comparison.worsened_checks?.length > 0) && (
                  <Card className="border border-red-100 shadow-sm overflow-hidden">
                    <div className="bg-red-50 px-6 py-3 border-b border-red-100">
                      <h3 className="text-sm font-black text-red-800 uppercase tracking-wider">New Vulnerabilities / Regressions</h3>
                    </div>
                    <div className="divide-y divide-gray-100">
                      {comparison.worsened_checks.map((check) => (
                        <div key={check.check_id} className="px-6 py-4 flex items-center justify-between hover:bg-gray-50 transition-colors">
                          <span className="font-bold text-gray-900">{check.check_name}</span>
                          <div className="flex items-center gap-3">
                            <Badge variant="success" size="sm">{check.scan1}</Badge>
                            <ArrowLeftIcon className="w-3 h-3 text-gray-300 rotate-180" />
                            <Badge variant="danger" size="sm">{check.scan2}</Badge>
                          </div>
                        </div>
                      ))}
                    </div>
                  </Card>
                )}
                
                {(comparison.unchanged_checks?.length > 0) && (
                    <details className="group">
                        <summary className="flex items-center justify-between p-4 bg-white border border-gray-200 rounded-xl cursor-pointer hover:bg-gray-50 transition-colors list-none">
                            <span className="text-sm font-black text-gray-500 uppercase tracking-widest">Unchanged Checks ({comparison.unchanged_checks.length})</span>
                            <ChevronDownIcon className="w-5 h-5 text-gray-400 group-open:rotate-180 transition-transform" />
                        </summary>
                        <Card className="mt-2 border-gray-100 shadow-sm">
                            <div className="divide-y divide-gray-50 max-h-64 overflow-y-auto">
                                {comparison.unchanged_checks.map((check) => (
                                    <div key={check.check_id} className="px-6 py-3 flex items-center justify-between text-sm">
                                        <span className="text-gray-600 font-medium">{check.check_name}</span>
                                        <Badge variant={check.result === 'Y' ? 'success' : 'danger'} size="sm">{check.result}</Badge>
                                    </div>
                                ))}
                            </div>
                        </Card>
                    </details>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
