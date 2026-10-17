// src/pages/Login.jsx
import { useState } from 'react';
import { useNavigate, Navigate, Link, useLocation } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import {
  UserIcon,
  LockClosedIcon,
  CheckCircleIcon,
  ExclamationCircleIcon,
} from '@heroicons/react/outline';
import { EyeIcon } from "@heroicons/react/solid";
import { Card } from "../components/ui/Card";

import Button from '../components/ui/Button';
import Input from '../components/ui/Input';
import { cn } from '../utils/cn';

const Login = () => {
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [isAdmin, setIsAdmin] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const successMessage = location.state?.message;

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    const result = await login(identifier, password, isAdmin);

    if (result.success) {
      navigate('/dashboard');
    } else {
      setError(result.error);
    }

    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4 sm:px-6 lg:px-8 py-12">
      <div className="max-w-md w-full space-y-6">
        {/* Header */}
        <div className="text-center">
          <div className="mx-auto w-16 h-16 bg-black rounded-full flex items-center justify-center mb-4 shadow-xl">
            <EyeIcon className="w-10 h-10 text-white" />
          </div>
          <h1 className="text-3xl font-black text-gray-900 mb-2 tracking-tight uppercase text-center">M O C K  D R I L L</h1>
          <p className="text-sm text-gray-500 font-medium">Compliance & Security Audit Platform</p>
        </div>

        {/* Role Toggle */}
        <div className="flex p-1 bg-gray-200 rounded-lg">
          <button
            onClick={() => setIsAdmin(false)}
            className={cn(
              "flex-1 py-2 text-xs font-bold uppercase tracking-wider rounded-md transition-all",
              !isAdmin ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"
            )}
          >
            User Login
          </button>
          <button
            onClick={() => setIsAdmin(true)}
            className={cn(
              "flex-1 py-2 text-xs font-bold uppercase tracking-wider rounded-md transition-all",
              isAdmin ? "bg-black text-white shadow-sm" : "text-gray-500 hover:text-gray-700"
            )}
          >
            Admin Login
          </button>
        </div>

        {/* Success Message */}
        {successMessage && (
          <Card className="border border-success-200 bg-success-50">
            <div className="flex items-start gap-3 p-4">
              <CheckCircleIcon className="w-5 h-5 text-success-600 mt-0.5 flex-shrink-0" />
              <p className="text-sm text-success-800">{successMessage}</p>
            </div>
          </Card>
        )}

        {/* Error Message */}
        {error && (
          <Card className="border border-danger-200 bg-danger-50">
            <div className="flex items-start gap-3 p-4">
              <ExclamationCircleIcon className="w-5 h-5 text-danger-600 mt-0.5 flex-shrink-0" />
              <div>
                <p className="text-sm font-medium text-danger-800">Login Failed</p>
                <p className="text-sm text-danger-700 mt-1">{error}</p>
              </div>
            </div>
          </Card>
        )}

        {/* Form Card */}
        <Card className="border border-gray-200 shadow-lg">
          <div className="p-6 sm:p-8">
            <form onSubmit={handleSubmit} className="space-y-6">
              {/* Username or Email */}
              <div>
                <label htmlFor="identifier" className="block text-sm font-medium text-gray-700 mb-2">
                  Username or Email
                </label>
                <Input
                  id="identifier"
                  type="text"
                  value={identifier}
                  onChange={(e) => setIdentifier(e.target.value)}
                  placeholder="Enter your username or email"
                  disabled={loading}
                  required
                  autoComplete="username"
                  icon={<UserIcon className="w-5 h-5 text-gray-400" />}
                />
              </div>

              {/* Password */}
              <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-2">
                  Password
                </label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  disabled={loading}
                  required
                  autoComplete="current-password"
                  icon={<LockClosedIcon className="w-5 h-5 text-gray-400" />}
                />
              </div>

              {/* Submit Button */}
              <Button
                type="submit"
                variant="primary"
                size="lg"
                className="w-full"
                disabled={loading}
              >
                {loading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2" />
                    Signing in...
                  </>
                ) : (
                  'Sign In'
                )}
              </Button>
            </form>
          </div>
        </Card>

        {/* Register Link */}
        <div className="text-center">
          <p className="text-sm text-gray-600">
            Don't have an account?{' '}
            <Link
              to="/register"
              className="font-medium text-primary-600 hover:text-primary-700 transition-colors"
            >
              Create one now
            </Link>
          </p>
        </div>

        {/* Security Notice */}
        <div className="text-center">
          <p className="text-xs text-gray-500 flex items-center justify-center gap-1">
            <LockClosedIcon className="w-4 h-4" />
            Your connection is secure and encrypted
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;
