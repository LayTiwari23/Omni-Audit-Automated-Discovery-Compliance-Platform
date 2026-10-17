import React from 'react';
import { cn } from '../utils/cn';

const colorMap = {
  // Auto: Deep Purple
  auto:    'bg-purple-100 text-purple-700 border-purple-200 shadow-sm',
  // Web: Bright Blue
  web:     'bg-blue-100 text-blue-700 border-blue-200 shadow-sm',
  // DNS: Rich Indigo
  dns:     'bg-indigo-100 text-indigo-700 border-indigo-200 shadow-sm',
  // Email: Fresh Emerald/Green
  email:   'bg-emerald-100 text-emerald-700 border-emerald-200 shadow-sm',
  // Network: Warm Amber/Orange
  network: 'bg-amber-100 text-amber-700 border-amber-200 shadow-sm',
  // SSH: Modern Violet
  ssh:     'bg-violet-100 text-violet-700 border-violet-200 shadow-sm',
  // FTP: Vivid Pink/Rose
  ftp:     'bg-rose-100 text-rose-700 border-rose-200 shadow-sm',
  // VPN: Teal/Cyan
  vpn:     'bg-cyan-100 text-cyan-700 border-cyan-200 shadow-sm',
};

export default function ScanTypeBadge({ type }) {
  if (!type) return null;

  // Handle comma-separated list of engines
  const engines = type.split(',').map(e => e.trim().toLowerCase());

  return (
    <div className="flex flex-wrap gap-1">
      {engines.map((engine, idx) => {
        const colorClass = colorMap[engine] || 'bg-gray-100 text-gray-700 border-gray-200';
        return (
          <span
            key={idx}
            className={cn(
              'inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-black border uppercase tracking-wider',
              colorClass
            )}
          >
            {engine}
          </span>
        );
      })}
    </div>
  );
}
