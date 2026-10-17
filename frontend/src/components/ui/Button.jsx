import React from 'react';
import { cn } from '../../utils/cn';

const Button = React.forwardRef(
  (
    {
      children,
      variant = 'primary',
      size = 'md',
      isLoading = false,
      disabled = false,
      className = '',
      type = 'button',
      as: Component = 'button', // default to 'button' if no 'as' prop
      ...props
    },
    ref
  ) => {
    const baseStyles =
      'inline-flex items-center justify-center font-medium rounded-lg transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed';

    const variants = {
      primary:
        'bg-primary-600 text-white hover:bg-primary-700 focus:ring-primary-500',
      secondary:
        'bg-gray-200 text-gray-900 hover:bg-gray-300 focus:ring-gray-400',
      outline:
        'border border-gray-300 bg-transparent text-gray-700 hover:bg-gray-50 focus:ring-primary-500',
      ghost:
        'bg-transparent text-gray-700 hover:bg-gray-100 focus:ring-gray-400',
      danger:
        'bg-danger-600 text-white hover:bg-danger-700 focus:ring-danger-500',
    };

    const sizes = {
      sm: 'px-3 py-1.5 text-sm',
      md: 'px-4 py-2 text-sm',
      lg: 'px-6 py-3 text-base',
    };

    const isDisabled = disabled || isLoading;

    // If the component is not a native button, we cannot pass the 'disabled' attribute,
    // but we can add aria-disabled and a class to indicate it's disabled.
    const extraProps = {};
    if (Component !== 'button') {
      extraProps['aria-disabled'] = isDisabled;
      extraProps['data-disabled'] = isDisabled;
    }

    return (
      <Component
        ref={ref}
        type={Component === 'button' ? type : undefined}
        className={cn(
          baseStyles,
          variants[variant],
          sizes[size],
          isDisabled && 'opacity-50 pointer-events-none cursor-not-allowed',
          className
        )}
        disabled={Component === 'button' ? isDisabled : undefined}
        {...extraProps}
        {...props}
      >
        {isLoading && (
          <svg
            className="w-4 h-4 mr-2 -ml-1 animate-spin"
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
          >
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            />
          </svg>
        )}
        {children}
      </Component>
    );
  }
);

Button.displayName = 'Button';

export default Button;
