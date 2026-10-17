import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { PlusIcon, PencilIcon, TrashIcon, CalendarIcon, ClockIcon, GlobeAltIcon, ChipIcon } from '@heroicons/react/outline';
import { listSchedules, deleteSchedule } from '../api/api';
import api from '../api/api';
import Button from '../components/ui/Button';
import { Card, CardContent } from "../components/ui/Card";
import Spinner from '../components/ui/Spinner';
import toast from 'react-hot-toast';
import Badge from '../components/ui/Badge';
import ScanTypeBadge from '../components/ScanTypeBadge';
import { formatToIST } from '../utils/date';

const daysOfWeek = {
  '0': 'Sunday', '1': 'Monday', '2': 'Tuesday', '3': 'Wednesday', '4': 'Thursday', '5': 'Friday', '6': 'Saturday'
};

const months = [
  'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
];

/**
 * Convert cron to human-readable text
 */
function formatCron(cron) {
  try {
    const parts = cron.split(' ');
    if (parts.length !== 5) return cron;

    const [min, hour, dom, month, dow] = parts;
    const time = `${hour.padStart(2, '0')}:${min.padStart(2, '0')}`;

    if (dom === '*' && month === '*' && dow === '*') {
      return `Daily at ${time}`;
    } else if (dow !== '*') {
      return `Weekly on ${daysOfWeek[dow] || 'unknown day'} at ${time}`;
    } else if (dom !== '*' && month === '*') {
      return `Monthly on the ${dom}${getOrdinal(dom)} at ${time}`;
    } else if (dom !== '*' && month !== '*') {
      return `Once on ${dom} ${months[parseInt(month, 10) - 1]} at ${time}`;
    }
    return cron;
  } catch (e) {
    return cron;
  }
}

function getOrdinal(n) {
  const s = ["th", "st", "nd", "rd"];
  const v = n % 100;
  return s[(v - 20) % 10] || s[v] || s[0];
}

export default function Schedules() {
  const [schedules, setSchedules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scannerIp, setScannerIp] = useState(null);

  const load = async () => {
    setLoading(true);
    try {
      const data = await listSchedules();
      setSchedules(data || []);
      
      // Fetch scanner IP
      const stats = await api.get('/dashboard/stats');
      setScannerIp(stats.data?.health?.scanner_ip);
    } catch (e) {
      toast.error(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleDelete = async (id, name) => {
    if (!window.confirm(`Delete schedule "${name}"?\nThis action cannot be undone.`)) return;
    try {
      await deleteSchedule(id);
      toast.success('Schedule deleted');
      load();
    } catch (e) {
      toast.error(e.message);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-50">
        <Spinner size="lg" className="text-primary-600" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-5xl mx-auto">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Automation Schedules</h1>
            <p className="text-gray-600 mt-1">Manage your recurring security assessments and continuous monitoring.</p>
          </div>
          <Link to="/schedules/new">
            <Button variant="primary" className="shadow-sm">
              <PlusIcon className="w-4 h-4 mr-2" />
              New Schedule
            </Button>
          </Link>
        </div>

        {schedules.length === 0 ? (
          <Card className="border-dashed border-2 border-gray-200">
            <CardContent className="py-20 text-center">
              <CalendarIcon className="w-16 h-16 mx-auto text-gray-300 mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">No schedules configured</h3>
              <p className="text-gray-500 mb-8 max-w-sm mx-auto">
                Keep your infrastructure secure by scheduling automatic recurring scans.
              </p>
              <Link to="/schedules/new">
                <Button variant="primary">Create your first schedule</Button>
              </Link>
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-4">
            {schedules.map((s) => (
              <Card key={s.id} className="hover:shadow-md transition-shadow border-gray-200 group">
                <CardContent className="p-6">
                  <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
                    <div className="flex-1 space-y-3">
                      <div className="flex items-center gap-3">
                        <h3 className="text-xl font-bold text-gray-900 group-hover:text-primary-600 transition-colors">
                          {s.name}
                        </h3>
                        <ScanTypeBadge type={s.scan_type} />

                        {s.enabled ? (
                          <Badge variant="success" size="sm">Active</Badge>
                        ) : (
                          <Badge variant="secondary" size="sm">
                            {s.cron_expression.split(' ')[2] !== '*' && s.cron_expression.split(' ')[3] !== '*' ? 'Finished' : 'Paused'}
                          </Badge>
                        )}

                        {s.last_run_status && (
                          <Badge 
                            variant={
                              s.last_run_status === 'COMPLETED' ? 'success' : 
                              s.last_run_status === 'FAILED' ? 'danger' : 
                              s.last_run_status === 'RUNNING' ? 'info' : 'warning'
                            } 
                            size="sm"
                            className="uppercase tracking-wider text-[10px]"
                          >
                            Last Scan: {s.last_run_status}
                          </Badge>
                        )}
                      </div>

                      {scannerIp && (
                        <div className="flex">
                          <div className="px-2 py-0.5 bg-indigo-50 text-indigo-700 border border-indigo-100 rounded-full text-[9px] font-black uppercase tracking-widest flex items-center gap-1 shadow-sm">
                            <span className="w-1 h-1 bg-indigo-500 rounded-full animate-pulse"></span>
                            Checks performed by: {scannerIp}
                          </div>
                        </div>
                      )}
                      
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-y-2 gap-x-8 text-sm text-gray-600">
                        <div className="flex items-center gap-2">
                          <GlobeAltIcon className="w-4 h-4 text-gray-400" />
                          <span className="font-medium">Target:</span>
                          <span className="font-mono bg-gray-100 px-1.5 py-0.5 rounded text-gray-700">{s.target}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <ClockIcon className="w-4 h-4 text-gray-400" />
                          <span className="font-medium">Frequency:</span>
                          <span className="text-primary-600 font-semibold">{formatCron(s.cron_expression)}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <ChipIcon className="w-4 h-4 text-gray-400" />
                          <span className="font-medium">Engine Mode:</span>
                          <span className="uppercase text-[10px] bg-indigo-50 text-indigo-700 border border-indigo-100 px-2 py-0.5 rounded-full font-bold">
                            {s.scan_mode === 'intelligent' || s.scan_mode === 'Auto-Discovery' ? 'Intelligent Auto-Discovery' : s.scan_mode.replace('_', ' ')}
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <CalendarIcon className="w-4 h-4 text-gray-400" />
                          <span className="font-medium">Next run:</span>
                          <span className="text-gray-900 italic">
                            {s.enabled ? formatToIST(s.next_run) : 'Not scheduled'}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-3 lg:border-l lg:pl-6 border-gray-100">
                      <Link to={`/schedules/${s.id}/edit`}>
                        <Button variant="outline" size="sm" className="hover:bg-primary-50 hover:text-primary-600 border-gray-200">
                          <PencilIcon className="w-4 h-4 mr-2" />
                          Edit
                        </Button>
                      </Link>
                      <Button 
                        variant="ghost" 
                        size="sm" 
                        onClick={() => handleDelete(s.id, s.name)}
                        className="text-rose-500 hover:bg-rose-50 hover:text-rose-700"
                      >
                        <TrashIcon className="w-4 h-4 mr-2" />
                        Delete
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
