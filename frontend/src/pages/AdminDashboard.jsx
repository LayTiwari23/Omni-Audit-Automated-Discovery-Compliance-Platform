import React, { useState, useEffect } from 'react';
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  PieChart, Pie, Cell
} from 'recharts';
import { 
  ShieldCheckIcon, 
  UsersIcon, 
  ServerIcon, 
  DatabaseIcon, 
  ExclamationIcon,
  TrashIcon,
  LockClosedIcon,
  ClockIcon,
  FingerPrintIcon,
  ClipboardListIcon
} from '@heroicons/react/outline';
import api from '../api/api';
import toast from 'react-hot-toast';
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/Card';
import Button from '../components/ui/Button';
import Spinner from '../components/ui/Spinner';
import StatsCard from '../components/StatsCard';
import { formatToIST } from '../utils/date';

const COLORS = ['#6366f1', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899'];

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

export default function AdminDashboard() {
  const [loading, setLoading] = useState(true);
  const [heatmap, setHeatmap] = useState([]);
  const [performance, setPerformance] = useState([]);
  const [queue, setQueue] = useState({ queued: 0, active: 0 });
  const [auditLogs, setAuditLogs] = useState([]);
  const [blacklist, setBlacklist] = useState([]);
  const [newBlacklist, setNewBlacklist] = useState({ target: '', reason: '' });
  
  const fetchData = async () => {
    if (heatmap.length === 0) setLoading(true);
    try {
      const results = await Promise.allSettled([
        api.get('/admin/stats/compliance-heatmap'),
        api.get('/admin/stats/engine-performance'),
        api.get('/admin/stats/queue-depth'),
        api.get('/admin/audit-logs'),
        api.get('/admin/blacklist')
      ]);

      if (results[0].status === 'fulfilled') setHeatmap(results[0].value.data);
      if (results[1].status === 'fulfilled') setPerformance(results[1].value.data);
      if (results[2].status === 'fulfilled') setQueue(results[2].value.data);
      if (results[3].status === 'fulfilled') setAuditLogs(results[3].value.data);
      if (results[4].status === 'fulfilled') setBlacklist(results[4].value.data);
    } catch (err) {
      toast.error('Failed to connect to admin services');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleCleanup = async (days) => {
    if (!window.confirm(`Are you sure you want to delete all scans older than ${days} days?`)) return;
    try {
      const res = await api.post(`/admin/maintenance/cleanup?days=${days}`);
      toast.success(`Cleanup successful: ${res.data.deleted_count} scans removed`);
      fetchData();
    } catch (err) {
      toast.error('Cleanup failed');
    }
  };

  const addToBlacklist = async () => {
    if (!newBlacklist.target) return;
    try {
      await api.post(`/admin/blacklist?target=${newBlacklist.target}&reason=${newBlacklist.reason}`);
      toast.success('Added to blacklist');
      setNewBlacklist({ target: '', reason: '' });
      fetchData();
    } catch (err) {
      toast.error('Failed to add to blacklist');
    }
  };

  if (loading && heatmap.length === 0) {
    return (
      <div className="flex items-center justify-center h-screen">
        <Spinner size="lg" className="text-primary-600" />
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto p-6 space-y-8 animate-fade-in">
      {/* Header */}
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-black text-gray-900 tracking-tight">Admin Control Plane</h1>
          <p className="text-gray-500 mt-1 font-medium italic">Platform-wide governance and advanced analytics</p>
        </div>
        <div className="flex gap-2 text-xs font-medium text-gray-400 bg-white px-3 py-1.5 rounded-lg border border-gray-100 shadow-sm shadow-black/5">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span>
            System Operational
          </span>
        </div>
      </div>

      {/* Top Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatsCard 
          label="Worker Queue" 
          value={queue.queued} 
          sub="Pending Celery tasks"
          icon={<ServerIcon className="w-8 h-8" />} 
          color="blue"
        />
        <StatsCard 
          label="Active Scans" 
          value={queue.active} 
          sub="Currently processing"
          icon={<ClipboardListIcon className="w-8 h-8" />} 
          color="green"
        />
        <StatsCard 
          label="Critical Vulns" 
          value={auditLogs.filter(l => l.action.includes('CRITICAL')).length} 
          sub="Detected in last 24h"
          icon={<ExclamationIcon className="w-8 h-8" />} 
          color="red"
        />
        <StatsCard 
          label="Blocked Targets" 
          value={blacklist.length} 
          sub="Platform-wide blacklist"
          icon={<LockClosedIcon className="w-8 h-8" />} 
          color="amber"
        />
      </div>

      {/* Analytics Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <Card className="shadow-2xl border-gray-100 overflow-hidden rounded-2xl ring-1 ring-black/5">
          <CardHeader className="bg-gray-50/50 border-b border-gray-100">
            <CardTitle className="text-sm font-black flex items-center gap-2 uppercase tracking-widest text-gray-500">
              <UsersIcon className="w-4 h-4 text-primary-500" />
              Compliance Heatmap
            </CardTitle>
          </CardHeader>
          <CardContent className="p-6 h-80">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={heatmap}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f1f5f9" />
                <XAxis dataKey="group" fontSize={10} axisLine={false} tickLine={false} />
                <YAxis fontSize={10} axisLine={false} tickLine={false} domain={[0, 100]} />
                <Tooltip 
                  cursor={{fill: '#f8fafc'}}
                  contentStyle={{borderRadius: '12px', border: 'none', boxShadow: '0 10px 25px rgba(0,0,0,0.1)'}}
                />
                <Bar dataKey="score" radius={[4, 4, 0, 0]} barSize={40}>
                  {heatmap.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.score > 80 ? '#10b981' : entry.score > 50 ? '#f59e0b' : '#ef4444'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card className="shadow-2xl border-gray-100 overflow-hidden rounded-2xl ring-1 ring-black/5">
          <CardHeader className="bg-gray-50/50 border-b border-gray-100">
            <CardTitle className="text-sm font-black flex items-center gap-2 uppercase tracking-widest text-gray-500">
              <ServerIcon className="w-4 h-4 text-green-500" />
              Engine Distribution
            </CardTitle>
          </CardHeader>
          <CardContent className="p-6 h-80">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={performance}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={8}
                  dataKey="total"
                  nameKey="engine"
                  label={renderCustomizedLabel}
                  stroke="none"
                >
                  {performance.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend 
                  layout="horizontal" 
                  verticalAlign="bottom" 
                  align="center"
                  iconType="circle" 
                  wrapperStyle={{ fontSize: '10px', paddingTop: '20px' }} 
                />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <Card className="lg:col-span-2 shadow-2xl border-gray-100 overflow-hidden rounded-2xl ring-1 ring-black/5">
          <CardHeader className="bg-gray-50/50 border-b border-gray-100 flex flex-row items-center justify-between">
            <CardTitle className="text-sm font-black flex items-center gap-2 uppercase tracking-widest text-gray-500">
              <FingerPrintIcon className="w-4 h-4 text-purple-500" />
              Governance Audit Logs
            </CardTitle>
            <Button variant="ghost" size="sm" onClick={fetchData} className="h-8 text-[10px] font-black uppercase tracking-widest">
              <ClockIcon className="w-4 h-4 mr-1.5" />
              Sync
            </Button>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto max-h-[400px]">
              <table className="min-w-full divide-y divide-gray-100">
                <thead className="bg-white sticky top-0 z-10 shadow-sm">
                  <tr>
                    <th className="px-6 py-4 text-left text-[10px] font-black text-gray-400 uppercase tracking-widest">Timestamp</th>
                    <th className="px-6 py-4 text-left text-[10px] font-black text-gray-400 uppercase tracking-widest">User</th>
                    <th className="px-6 py-4 text-left text-[10px] font-black text-gray-400 uppercase tracking-widest">Action</th>
                    <th className="px-6 py-4 text-left text-[10px] font-black text-gray-400 uppercase tracking-widest">Details</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-50">
                  {auditLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-gray-50/50 transition-colors">
                      <td className="px-6 py-4 whitespace-nowrap text-[10px] font-bold text-gray-400 font-mono">
                        {formatToIST(log.timestamp)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-xs font-black text-gray-900">
                        {log.user}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded-lg text-[9px] font-black uppercase tracking-tighter ${
                          log.action.includes('DELETE') ? 'bg-red-50 text-red-600' :
                          log.action.includes('CHANGE') ? 'bg-orange-50 text-orange-600' :
                          'bg-primary-50 text-primary-600'
                        }`}>
                          {log.action}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-[10px] text-gray-500 font-medium italic truncate max-w-xs">
                        {log.details}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>

        <div className="space-y-8">
          <Card className="shadow-2xl border-gray-100 overflow-hidden rounded-2xl ring-1 ring-black/5">
            <CardHeader className="bg-gray-50/50 border-b border-gray-100">
              <CardTitle className="text-sm font-black flex items-center gap-2 uppercase tracking-widest text-gray-500">
                <LockClosedIcon className="w-4 h-4 text-red-500" />
                Blacklist
              </CardTitle>
            </CardHeader>
            <CardContent className="p-6">
              <div className="space-y-4">
                <div className="flex gap-2">
                  <input 
                    type="text" 
                    placeholder="IP or Domain" 
                    className="flex-1 text-xs border-2 border-gray-100 rounded-xl px-4 py-2 outline-none focus:border-red-500 transition-colors"
                    value={newBlacklist.target}
                    onChange={(e) => setNewBlacklist({...newBlacklist, target: e.target.value})}
                  />
                  <Button size="sm" className="bg-red-600 hover:bg-red-700 text-white rounded-xl shadow-lg shadow-red-500/20" onClick={addToBlacklist}>Block</Button>
                </div>
                <div className="space-y-2 max-h-40 overflow-y-auto pr-2">
                  {blacklist.map(item => (
                    <div key={item.id} className="flex justify-between items-center p-3 bg-gray-50 rounded-xl border border-gray-100 group">
                      <div className="min-w-0">
                        <p className="text-xs font-black text-gray-900 truncate">{item.target}</p>
                        <p className="text-[9px] text-gray-400 truncate font-medium">{item.reason || 'No reason provided'}</p>
                      </div>
                      <button 
                        onClick={() => api.delete(`/admin/blacklist/${item.id}`).then(fetchData)}
                        className="text-gray-300 hover:text-red-600 transition-colors p-1"
                      >
                        <TrashIcon className="w-4 h-4" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="shadow-2xl border-gray-100 overflow-hidden rounded-2xl ring-1 ring-black/5">
            <CardHeader className="bg-gray-50/50 border-b border-gray-100">
              <CardTitle className="text-sm font-black flex items-center gap-2 uppercase tracking-widest text-gray-500">
                <DatabaseIcon className="w-4 h-4 text-amber-500" />
                Maintenance
              </CardTitle>
            </CardHeader>
            <CardContent className="p-6">
              <div className="space-y-4">
                <div>
                  <p className="text-[10px] font-black text-gray-400 uppercase tracking-widest mb-3">Garbage Collection</p>
                  <div className="grid grid-cols-2 gap-2">
                    <Button 
                      variant="outline" 
                      size="sm" 
                      className="text-[10px] font-bold h-10 border-gray-200 rounded-xl hover:bg-gray-50"
                      onClick={() => handleCleanup(90)}
                    >
                      90 Days
                    </Button>
                    <Button 
                      variant="outline" 
                      size="sm" 
                      className="text-[10px] font-bold h-10 border-gray-200 rounded-xl hover:bg-gray-50"
                      onClick={() => handleCleanup(365)}
                    >
                      1 Year
                    </Button>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
