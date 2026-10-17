// src/components/ui/Select.jsx
import React from 'react';
import { cn } from '../../utils/cn';

const Select = React.forwardRef(
  ({ className = '', children, error, ...props }, ref) => {
    return (
      <select
        className={cn(
          'flex h-10 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50',
          error && 'border-danger-500 focus:ring-danger-500',
          className
        )}
        ref={ref}
        {...props}
      >
        {children}
      </select>
    );
  }
);

Select.displayName = 'Select';

export default Select;
