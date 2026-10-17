// src/components/ui/Badge.jsx
import React from 'react';
import { cn } from '../../utils/cn';

const Badge = React.forwardRef(
  (
    {
      children,
      variant = 'default', // default, success, danger, warning, info, outline
      size = 'md',          // sm, md
      className = '',
      ...props
    },
    ref
  ) => {
    const variants = {
      default: 'bg-gray-100 text-gray-800',
      success: 'bg-success-100 text-success-800',
      danger: 'bg-danger-100 text-danger-800',
      warning: 'bg-warning-100 text-warning-800',
      info: 'bg-primary-100 text-primary-800',
      outline: 'bg-transparent border border-gray-300 text-gray-700',
    };

    const sizes = {
      sm: 'px-2 py-0.5 text-xs',
      md: 'px-2.5 py-0.5 text-sm',
    };

    return (
      <span
        ref={ref}
        className={cn(
          'inline-flex items-center font-medium rounded-full',
          variants[variant],
          sizes[size],
          className
        )}
        {...props}
      >
        {children}
      </span>
    );
  }
);

Badge.displayName = 'Badge';

export default Badge;
