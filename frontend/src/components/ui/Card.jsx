import React from 'react';
import { cn } from '../../utils/cn';

const Card = React.forwardRef(
  ({ children, className = '', padding = true, ...props }, ref) => {
    const paddingClass =
      padding === true
        ? 'p-6'
        : padding === false
        ? ''
        : padding; // allow custom padding string

    return (
      <div
        ref={ref}
        className={cn(
          'bg-white rounded-xl border border-gray-200 shadow-sm',
          paddingClass,
          className
        )}
        {...props}
      >
        {children}
      </div>
    );
  }
);

Card.displayName = 'Card';

const CardHeader = React.forwardRef(
  ({ children, className = '', ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn('mb-4 flex items-center justify-between', className)}
        {...props}
      >
        {children}
      </div>
    );
  }
);

CardHeader.displayName = 'CardHeader';

const CardTitle = React.forwardRef(
  ({ children, className = '', ...props }, ref) => {
    return (
      <h3
        ref={ref}
        className={cn('text-lg font-semibold text-gray-900', className)}
        {...props}
      >
        {children}
      </h3>
    );
  }
);

CardTitle.displayName = 'CardTitle';

const CardDescription = React.forwardRef(
  ({ children, className = '', ...props }, ref) => {
    return (
      <p
        ref={ref}
        className={cn('text-sm text-gray-500', className)}
        {...props}
      >
        {children}
      </p>
    );
  }
);

CardDescription.displayName = 'CardDescription';

const CardContent = React.forwardRef(
  ({ children, className = '', ...props }, ref) => {
    return (
      <div ref={ref} className={cn('', className)} {...props}>
        {children}
      </div>
    );
  }
);

CardContent.displayName = 'CardContent';

const CardFooter = React.forwardRef(
  ({ children, className = '', ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn('mt-4 flex items-center justify-end space-x-2', className)}
        {...props}
      >
        {children}
      </div>
    );
  }
);

CardFooter.displayName = 'CardFooter';

export { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter };
