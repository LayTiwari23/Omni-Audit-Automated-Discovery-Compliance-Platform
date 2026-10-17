// src/components/StatsCard.jsx
import React from 'react';
import { Card } from './ui/Card';
import { cn } from '../utils/cn';

const colorVariants = {
  blue:   { bg: 'bg-primary-50', text: 'text-primary-700', icon: 'text-primary-500' },
  green:  { bg: 'bg-success-50', text: 'text-success-700', icon: 'text-success-500' },
  red:    { bg: 'bg-danger-50',  text: 'text-danger-700',  icon: 'text-danger-500'  },
  yellow: { bg: 'bg-warning-50', text: 'text-warning-700', icon: 'text-warning-500' },
  purple: { bg: 'bg-purple-50', text: 'text-purple-700', icon: 'text-purple-500' },
  violet: { bg: 'bg-violet-500/10', text: 'text-violet-400', icon: 'text-violet-400' },
  emerald: { bg: 'bg-emerald-500/10', text: 'text-emerald-400', icon: 'text-emerald-400' },
  rose:   { bg: 'bg-rose-500/10', text: 'text-rose-400', icon: 'text-rose-400' },
  amber:  { bg: 'bg-amber-500/10', text: 'text-amber-400', icon: 'text-amber-400' },
  teal:   { bg: 'bg-teal-500/10', text: 'text-teal-400', icon: 'text-teal-400' },
};

export default function StatsCard({ label, value, sub, color = "blue", icon, className = '' }) {
  const variant = colorVariants[color] || colorVariants.blue;

  return (
    <Card padding="p-5" className={cn('border-0', variant.bg, className)}>
      <div className="flex items-start gap-4">
        {icon && (
          <div className={cn('text-2xl flex-shrink-0', variant.icon)}>
            {icon}
          </div>
        )}
        <div className="min-w-0 flex-1">
          <p className="text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400 mb-1">
            {label}
          </p>
          <p className={cn('text-3xl font-bold leading-none', variant.text)}>
            {value ?? "—"}
          </p>
          {sub && (
            <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">{sub}</p>
          )}
        </div>
      </div>
    </Card>
  );
}
