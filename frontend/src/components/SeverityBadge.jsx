// src/components/SeverityBadge.jsx
import React from 'react';
import Badge from './ui/Badge';

const MAP = {
  critical: 'danger',
  high:     'danger',
  medium:   'warning',
  low:      'success',
  info:     'info',
};

export default function SeverityBadge({ severity, size = 'md', className = '' }) {
  const sev = (severity || 'info').toLowerCase();
  const variant = MAP[sev] || 'default';

  return (
    <Badge variant={variant} size={size} className={className}>
      {severity || 'N/A'}
    </Badge>
  );
}
