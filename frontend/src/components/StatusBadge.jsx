// src/components/StatusBadge.jsx
import React from 'react';
import Badge from './ui/Badge';

export default function StatusBadge({ status, size = 'md', className = '' }) {
  const isPass = status === 'PASS' || status === 'Y' || status === 'COMPLETED';
  const isRunning = status === 'RUNNING';
  const isFailed = status === 'FAIL' || status === 'N' || status === 'FAILED';

  let variant = 'default';
  if (isPass) variant = 'success';
  if (isRunning) variant = 'info';
  if (isFailed) variant = 'danger';

  return (
    <Badge variant={variant} size={size} className={className}>
      {status}
    </Badge>
  );
}
