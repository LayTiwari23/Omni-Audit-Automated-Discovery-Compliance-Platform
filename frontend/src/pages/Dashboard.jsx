import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { 
  ShieldCheckIcon, 
  ExclamationIcon, 
  InformationCircleIcon,
  RefreshIcon,
  ClipboardListIcon,
  TrendingUpIcon,
  ClockIcon,
  ServerIcon,
  FilterIcon,
  DownloadIcon,
  ChevronRightIcon
} from '@heroicons/react/outline';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend
} from 'recharts';
import api, { BASE, getToken } from '../api';
import StatsCard from '../components/StatsCard';
import { Card, CardHeader, CardTitle } from '../components/ui/Card';
import Button from '../components/ui/Button';
import ScanTypeBadge from '../components/ScanTypeBadge';
import { formatTimeIST } from '../utils/date';
import { cn } from '../utils/cn';

const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899'];

const renderCustomizedLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, percent, index, name }) => {
  const RADIAN = Math.PI / 180;
  const radius = outerRadius + 25;
  const x = cx + radius * Math.cos(-midAngle * RADIAN);
  const y = cy + radius * Math.sin(-midAngle * RADIAN);

  return (
    <text 
      x={x} 
      y={y} 
      fill="#4b5563" 
      textAnchor={x > cx ? 'start' : 'end'} 
      dominantBaseline="central"
      className="text-[10px] font-bold"
    >
      {`${name} (${(percent * 100).toFixed(0)}%)`}
    </text>
  );
};

const StatusIndicator = ({ status, label }) => (
  <div className="flex items-center gap-2 px-3 py-1 bg-gray-100 rounded-full border border-gray-200">
    <div className={`w-2 h-2 rounded-full ${status === 'up' ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}></div>
    <span className="text-xs font-semibold text-gray-600 uppercase tracking-wider">{label}</span>
  </div>
);

export default function Dashboard() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [days, setDays] = useState(30);

  useEffect(() => {
    async function fetchStats() {
      setLoading(true);
      try {
        const res = await api.get(`/dashboard/stats?days=${days}`);
        setData(res.data);
      } catch (err) {
        console.error("Dashboard data fetch failed:", err);
      } finally {
        setLoading(false);
      }
    }
    fetchStats();
  }, [days]);

  const downloadSummary = async () => {
    try {
      const url = `${BASE}/dashboard/download-summary?days=${days}`;
      const token = getToken();
      const res = await fetch(url, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (!res.ok) throw new Error('Failed to download');
      const blob = await res.blob();
      const a = document.createElement('a');
      a.href = window.URL.createObjectURL(blob);
      a.download = `Executive_Summary_${days}d.pdf`;
      a.click();
    } catch (err) {
      console.error(err);
      alert('Failed to download report');
    }
  };

  if (loading && !data) {
    return (
      <div className="flex items-center justify-center h-full">
        <RefreshIcon className="w-10 h-10 text-primary-600 animate-spin" />
      </div>
    );
  }

  const { kpis, trend, distribution, critical_targets, activity, health } = data;

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header & Filters */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-extrabold text-gray-900 tracking-tight">Executive Dashboard</h1>
          <p className="text-gray-500 text-sm mt-1">Real-time infrastructure security & compliance overview</p>
        </div>
        
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex bg-white rounded-lg shadow-sm border border-gray-200 p-1">
            {[7, 30, 90].map(d => (
              <button
                key={d}
                onClick={() => setDays(d)}
                className={`px-3 py-1.5 text-xs font-bold rounded-md transition-all ${
                  days === d ? 'bg-primary-600 text-white shadow-sm' : 'text-gray-500 hover:text-gray-700'
                }`}
              >
                {d}D
              </button>
            ))}
          </div>
          <Button variant="secondary" onClick={downloadSummary} className="flex items-center gap-2 text-xs py-2">
            <DownloadIcon className="w-4 h-4" />
            Executive Summary
          </Button>
          <Link to="/scan">
            <Button variant="primary" className="flex items-center gap-2 text-xs py-2">
              <ShieldCheckIcon className="w-4 h-4" />
              New Scan
            </Button>
          </Link>
        </div>
      </div>

      {/* System Health */}
      <div className="flex flex-wrap gap-4">
        <StatusIndicator status={health.api} label="API Service" />
        <StatusIndicator status={health.db} label="Database" />
        <StatusIndicator status={health.redis} label="Redis Cache" />
        <StatusIndicator status={health.celery} label="Task Workers" />
      </div>

      {/* KPI Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatsCard 
          label="Global Compliance" 
          value={`${kpis.avg_compliance}%`} 
          sub="Average across all targets"
          icon={<ShieldCheckIcon className="w-8 h-8" />} 
          color="primary"
        />
        <StatsCard 
          label="Critical Risks" 
          value={kpis.critical_vulns} 
          sub="Requires immediate action"
          icon={<ExclamationIcon className="w-8 h-8" />} 
          color="red"
        />
        <StatsCard 
          label="Active Scans" 
          value={kpis.total_scans} 
          sub="Total history count"
          icon={<ClipboardListIcon className="w-8 h-8" />} 
          color="purple"
        />
        <StatsCard 
          label="High Risks" 
          value={kpis.high_vulns} 
          sub="Significant security gaps"
          icon={<InformationCircleIcon className="w-8 h-8" />} 
          color="amber"
        />
      </div>

      {/* Main Analytics Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Compliance Trend Chart */}
        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 uppercase tracking-tight">
              <TrendingUpIcon className="w-5 h-5 text-primary-500" />
              Compliance Progress Trend
            </CardTitle>
          </CardHeader>
          <div className="h-[300px] w-full mt-4">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trend} margin={{ right: 20, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorComp" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.1}/>
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f3f4f6" />
                <XAxis 
                  dataKey="date" 
                  axisLine={false} 
                  tickLine={false} 
                  tick={{fontSize: 10, fill: '#9ca3af'}}
                  tickFormatter={(str) => {
                    const date = new Date(str);
                    return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
                  }}
                />
                <YAxis 
                  axisLine={false} 
                  tickLine={false} 
                  tick={{fontSize: 10, fill: '#9ca3af'}}
                  domain={[0, 100]}
                />
                <Tooltip 
                  contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                  labelStyle={{ fontWeight: 'bold', color: '#374151' }}
                />
                <Area 
                  type="monotone" 
                  dataKey="compliance" 
                  stroke="#3b82f6" 
                  strokeWidth={3}
                  fillOpacity={1} 
                  fill="url(#colorComp)" 
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>

        {/* Scan Distribution Pie */}
        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 uppercase tracking-tight">
              <ServerIcon className="w-5 h-5 text-primary-500" />
              Scan Distribution by Module
            </CardTitle>
          </CardHeader>
          <div className="h-[300px] w-full mt-4">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={distribution}
                  innerRadius={50}
                  outerRadius={70}
                  paddingAngle={5}
                  dataKey="value"
                  label={renderCustomizedLabel}
                  labelLine={{ stroke: '#9ca3af', strokeWidth: 1 }}
                >
                  {distribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend 
                  layout="horizontal" 
                  verticalAlign="bottom" 
                  align="center"
                  iconType="circle" 
                  wrapperStyle={{ fontSize: '10px', paddingTop: '10px' }} 
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top 5 Critical Targets */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-red-600 uppercase tracking-tight">
              <ExclamationIcon className="w-5 h-5" />
              Critical Targets requiring Remediation
            </CardTitle>
          </CardHeader>
          <div className="overflow-x-auto mt-4">
            <table className="min-w-full divide-y divide-gray-100">
              <thead>
                <tr className="bg-gray-50/50">
                  <th className="px-4 py-3 text-left text-[10px] font-bold text-gray-400 uppercase tracking-widest">Asset</th>
                  <th className="px-4 py-3 text-left text-[10px] font-bold text-gray-400 uppercase tracking-widest">Type</th>
                  <th className="px-4 py-3 text-right text-[10px] font-bold text-gray-400 uppercase tracking-widest">Score</th>
                  <th className="px-4 py-3 text-right"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {critical_targets.map(target => (
                  <tr key={target.id} className="group hover:bg-gray-50/80 transition-colors">
                    <td className="px-4 py-3 whitespace-nowrap text-sm font-semibold text-gray-700">{target.target}</td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <ScanTypeBadge type={target.type} />
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-right">
                      <span className={`text-xs font-black ${
                        target.compliance < 50 ? 'text-red-600' : target.compliance < 80 ? 'text-amber-600' : 'text-green-600'
                      }`}>
                        {target.compliance}%
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <Link to={`/reports/${target.id}`}>
                        <ChevronRightIcon className="w-4 h-4 text-gray-300 group-hover:text-primary-600 inline transition-colors" />
                      </Link>
                    </td>
                  </tr>
                ))}
                {critical_targets.length === 0 && (
                  <tr><td colSpan="4" className="py-10 text-center text-gray-400 italic text-sm">No critical vulnerabilities found</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>

        {/* Recent Activity Feed */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 uppercase tracking-tight">
              <ClockIcon className="w-5 h-5 text-primary-500" />
              Live Activity Feed
            </CardTitle>
          </CardHeader>
          <div className="mt-4 space-y-4 max-h-[400px] overflow-y-auto pr-2 custom-scrollbar">
            {activity.map((item) => (
              <div key={item.id} className="flex gap-4 p-3 rounded-lg border border-gray-100 hover:border-primary-100 transition-colors bg-gray-50/30">
                <div className="mt-1">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold ${
                    item.stage === 'ERROR' || item.stage === 'CRITICAL' ? 'bg-red-100 text-red-600' :
                    item.stage === 'DONE' ? 'bg-green-100 text-green-600' : 'bg-primary-100 text-primary-600'
                  }`}>
                    {item.stage[0]}
                  </div>
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex justify-between items-start mb-1">
                    <p className="text-xs font-bold text-gray-700 uppercase tracking-tighter text-[10px]">Scan #{item.scan_id} <span className="text-gray-400 font-normal">| {item.stage}</span></p>
                    <span className="text-[10px] text-gray-400 flex items-center gap-1">
                      <ClockIcon className="w-3 h-3" />
                      {formatTimeIST(item.timestamp)}
                    </span>
                  </div>
                  <p className="text-xs text-gray-600 truncate">{item.message}</p>
                </div>
              </div>
            ))}
            {activity.length === 0 && (
              <div className="py-10 text-center text-gray-400 italic text-sm">No recent activity detected</div>
            )}
          </div>
        </Card>
      </div>

      <style jsx>{`
        .custom-scrollbar::-webkit-scrollbar { width: 4px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #e2e8f0; border-radius: 10px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #cbd5e1; }
      `}</style>
    </div>
  );
}
