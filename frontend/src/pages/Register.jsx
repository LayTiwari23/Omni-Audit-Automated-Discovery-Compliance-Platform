// src/pages/Register.jsx
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  UserIcon,
  MailIcon,
  LockClosedIcon,
  CheckCircleIcon,
  ExclamationCircleIcon,
} from "@heroicons/react/outline";
import { EyeIcon } from "@heroicons/react/solid";
import { Card } from "../components/ui/Card";

import Button from "../components/ui/Button";
import Input from "../components/ui/Input";
import { cn } from "../utils/cn";
import toast from "react-hot-toast";
import * as api from "../api/api";

export default function Register() {
  const navigate = useNavigate();

  const [form, setForm] = useState({
    full_name: "",
    email: "",
    username: "",
    password: "",
    confirm_password: "",
    is_admin: false,
    admin_secret: "",
  });
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  function change(e) {
    setForm((f) => ({ ...f, [e.target.name]: e.target.value }));
    setError("");
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setSuccess("");

    if (form.password !== form.confirm_password) {
      setError("Passwords do not match.");
      return;
    }
    if (form.password.length < 6) {
      setError("Password must be at least 6 characters.");
      return;
    }

    setLoading(true);
    try {
      const payload = {
        full_name: form.full_name,
        email: form.email,
        username: form.username || null,
        password: form.password,
        is_admin: form.is_admin,
        admin_secret: form.is_admin ? form.admin_secret : null,
      };
      await api.register(payload);
      setSuccess("Registration successful! Redirecting to login...");
      toast.success("Account created!");
      setTimeout(() => navigate("/login"), 2000);
    } catch (err) {
      setError(err.message || "Registration failed. Try again.");
      toast.error("Registration failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <div className="flex justify-center">
          <div className="mx-auto w-16 h-16 bg-black rounded-full flex items-center justify-center mb-4 shadow-xl">
            <EyeIcon className="w-10 h-10 text-white" />
          </div>
        </div>
        <h2 className="mt-6 text-center text-3xl font-black text-gray-900 tracking-tight uppercase">
          M O C K  D R I L L
        </h2>

        <p className="mt-2 text-center text-sm text-gray-600 font-medium">
          Compliance & Security Audit Platform
        </p>
        <p className="mt-2 text-center text-sm text-gray-600">
          Already have an account?{" "}
          <Link to="/login" className="font-medium text-primary-600 hover:text-primary-500 transition-colors">
            Sign in here
          </Link>
        </p>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <Card>
          <form className="space-y-6" onSubmit={handleSubmit}>
            {error && (
              <div className="p-3 bg-danger-50 border border-danger-200 rounded-lg flex items-center gap-2 text-danger-700 text-sm animate-shake">
                <ExclamationCircleIcon className="w-5 h-5 flex-shrink-0" />
                {error}
              </div>
            )}

            {success && (
              <div className="p-3 bg-success-50 border border-success-200 rounded-lg flex items-center gap-2 text-success-700 text-sm">
                <CheckCircleIcon className="w-5 h-5 flex-shrink-0" />
                {success}
              </div>
            )}

            <div className="p-6">
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-1">
                    Full Name
                  </label>
                  <Input
                    name="full_name"
                    type="text"
                    required
                    placeholder="John Doe"
                    icon={<UserIcon className="h-5 w-5" />}
                    value={form.full_name}
                    onChange={change}
                  />
                </div>

                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-1">
                    Email Address
                  </label>
                  <Input
                    name="email"
                    type="email"
                    required
                    placeholder="john@example.com"
                    icon={<MailIcon className="h-5 w-5" />}
                    value={form.email}
                    onChange={change}
                  />
                </div>

                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-1">
                    Username (optional)
                  </label>
                  <Input
                    name="username"
                    type="text"
                    placeholder="johndoe"
                    value={form.username}
                    onChange={change}
                  />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-1">
                      Password
                    </label>
                    <Input
                      name="password"
                      type="password"
                      required
                      placeholder="••••••••"
                      icon={<LockClosedIcon className="h-5 w-5" />}
                      value={form.password}
                      onChange={change}
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-1">
                      Confirm Password
                    </label>
                    <Input
                      name="confirm_password"
                      type="password"
                      required
                      placeholder="••••••••"
                      value={form.confirm_password}
                      onChange={change}
                    />
                  </div>
                </div>

                <div className="pt-2 border-t border-gray-100">
                  <div className="flex items-center justify-between mb-4 mt-2">
                    <span className="text-sm font-semibold text-gray-700">Account Type</span>
                    <div className="flex bg-gray-100 p-1 rounded-lg">
                      <button
                        type="button"
                        onClick={() => setForm({ ...form, is_admin: false })}
                        className={cn(
                          "px-3 py-1 text-xs font-bold rounded-md transition-all",
                          !form.is_admin ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"
                        )}
                      >
                        User
                      </button>
                      <button
                        type="button"
                        onClick={() => setForm({ ...form, is_admin: true })}
                        className={cn(
                          "px-3 py-1 text-xs font-bold rounded-md transition-all",
                          form.is_admin ? "bg-primary-600 text-white shadow-sm" : "text-gray-500 hover:text-gray-700"
                        )}
                      >
                        Admin
                      </button>
                    </div>
                  </div>

                  {form.is_admin && (
                    <div className="mb-4">
                      <label className="block text-sm font-semibold text-gray-700 mb-1">
                        Admin Secret Key
                      </label>
                      <Input
                        name="admin_secret"
                        type="password"
                        required
                        placeholder="Enter key to register as admin"
                        value={form.admin_secret}
                        onChange={change}
                      />
                    </div>
                  )}
                </div>

                <Button
                  type="submit"
                  variant="primary"
                  className="w-full py-3"
                  disabled={loading}
                >
                  {loading ? "Creating Account..." : "Create Account"}
                </Button>
              </div>
            </div>
          </form>
        </Card>
      </div>
    </div>
  );
}
