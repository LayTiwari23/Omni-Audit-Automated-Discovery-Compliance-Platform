import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { getSchedule, createSchedule, updateSchedule } from '../api/api';
import Button from '../components/ui/Button';
import { Card, CardHeader, CardTitle, CardContent } from "../components/ui/Card";

import toast from 'react-hot-toast';

const SCAN_TYPES = [
  { id: 'web', label: 'Web Security' },
  { id: 'dns', label: 'DNS Compliance' },
  { id: 'email', label: 'Email Security' },
  { id: 'network', label: 'Network Probing' },
  { id: 'ssh', label: 'SSH Security' },
  { id: 'ftp', label: 'FTP Security' },
];

const SCAN_MODES = [
  { id: 'web_engine', label: 'Modular Web Engine' },
  { id: 'command_only', label: 'Command-based' },
  { id: 'pure_python', label: 'Pure Python' },
  { id: 'hybrid', label: 'Hybrid (Python + Command)' },
];

export default function ScheduleEdit() {
  const { id } = useParams();
  const navigate = useNavigate();
  const isEdit = Boolean(id);

  const [form, setForm] = useState({
    name: '',
    target: '',
    scan_type: 'web',
    scan_mode: 'command_only',
    cron_expression: '0 0 * * *', // Daily at midnight
    enabled: true,
  });

  useEffect(() => {
    if (isEdit) {
      getSchedule(id).then(setForm).catch(e => toast.error(e.message));
    }
  }, [id, isEdit]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      if (isEdit) {
        await updateSchedule(id, form);
        toast.success('Schedule updated');
      } else {
        await createSchedule(form);
        toast.success('Schedule created');
      }
      navigate('/schedules');
    } catch (e) {
      toast.error(e.message);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-2xl mx-auto px-4">
        <h1 className="text-3xl font-bold text-gray-900 mb-6">
          {isEdit ? 'Edit Schedule' : 'New Scheduled Scan'}
        </h1>

        <Card>
          <CardContent className="p-6">
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Friendly Name</label>
                <input
                  type="text"
                  required
                  className="w-full border-gray-300 rounded-lg shadow-sm focus:ring-primary-500 focus:border-primary-500"
                  value={form.name}
                  onChange={e => setForm({ ...form, name: e.target.value })}
                  placeholder="e.g. Weekly Production Web Scan"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Target (Domain or IP)</label>
                <input
                  type="text"
                  required
                  className="w-full border-gray-300 rounded-lg shadow-sm focus:ring-primary-500 focus:border-primary-500"
                  value={form.target}
                  onChange={e => setForm({ ...form, target: e.target.value })}
                  placeholder="example.com or 192.168.1.1"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Scan Type</label>
                  <select
                    className="w-full border-gray-300 rounded-lg shadow-sm focus:ring-primary-500 focus:border-primary-500"
                    value={form.scan_type}
                    onChange={e => setForm({ ...form, scan_type: e.target.value })}
                  >
                    {SCAN_TYPES.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Scan Mode</label>
                  <select
                    className="w-full border-gray-300 rounded-lg shadow-sm focus:ring-primary-500 focus:border-primary-500"
                    value={form.scan_mode}
                    onChange={e => setForm({ ...form, scan_mode: e.target.value })}
                  >
                    {SCAN_MODES.map(m => <option key={m.id} value={m.id}>{m.label}</option>)}
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Cron Expression</label>
                <input
                  type="text"
                  required
                  className="w-full border-gray-300 rounded-lg shadow-sm focus:ring-primary-500 focus:border-primary-500 font-mono"
                  value={form.cron_expression}
                  onChange={e => setForm({ ...form, cron_expression: e.target.value })}
                />
                <p className="mt-1 text-xs text-gray-500">
                  Format: <code>minute hour day month day_of_week</code>. <br/>
                  Example: <code>0 0 * * 0</code> (Weekly on Sunday at midnight)
                </p>
              </div>

              <div className="flex items-center gap-2 py-2">
                <input
                  type="checkbox"
                  id="enabled"
                  className="rounded text-primary-600 focus:ring-primary-500"
                  checked={form.enabled}
                  onChange={e => setForm({ ...form, enabled: e.target.checked })}
                />
                <label htmlFor="enabled" className="text-sm font-medium text-gray-700">Schedule Enabled</label>
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t">
                <Button type="button" variant="ghost" onClick={() => navigate('/schedules')}>
                  Cancel
                </Button>
                <Button type="submit" variant="primary">
                  {isEdit ? 'Update Schedule' : 'Create Schedule'}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
