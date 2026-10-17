// src/pages/Profile.jsx
import { useState, useEffect } from "react";
import { useAuth } from "../auth/AuthContext";
import {
  UserIcon,
  MailIcon,
  AtSymbolIcon,
  LockClosedIcon,
  ShieldCheckIcon,
  CameraIcon,
} from "@heroicons/react/outline";
import { Card, CardHeader, CardTitle, CardContent } from "../components/ui/Card";
import Button from "../components/ui/Button";
import Input from "../components/ui/Input";
import Badge from "../components/ui/Badge";
import Spinner from "../components/ui/Spinner";
import { updateProfile, changePassword } from "../api/api";
import toast from "react-hot-toast";
import { formatToIST } from "../utils/date";

export default function Profile() {
  const { user, refreshUser } = useAuth(); // get refreshUser
  const [loading, setLoading] = useState(false);
  const [form, setForm] = useState({
    full_name: "",
    username: "",
    email: "",
  });
  const [passwordForm, setPasswordForm] = useState({
    current_password: "",
    new_password: "",
    confirm_password: "",
  });
  const [passwordError, setPasswordError] = useState("");

  useEffect(() => {
    if (user) {
      setForm({
        full_name: user.full_name || "",
        username: user.username || "",
        email: user.email || "",
      });
    }
  }, [user]);

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handlePasswordChange = (e) => {
    setPasswordForm({ ...passwordForm, [e.target.name]: e.target.value });
    setPasswordError("");
  };

  const handleProfileSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await updateProfile(form);
      await refreshUser(); // refresh user data in context
      toast.success("Profile updated successfully");
    } catch (err) {
      toast.error(err.message || "Failed to update profile");
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordSubmit = async (e) => {
    e.preventDefault();
    if (passwordForm.new_password !== passwordForm.confirm_password) {
      setPasswordError("Passwords do not match");
      return;
    }
    if (passwordForm.new_password.length < 6) {
      setPasswordError("Password must be at least 6 characters");
      return;
    }
    setLoading(true);
    try {
      await changePassword({
        current_password: passwordForm.current_password,
        new_password: passwordForm.new_password,
      });
      setPasswordForm({ current_password: "", new_password: "", confirm_password: "" });
      toast.success("Password changed successfully");
    } catch (err) {
      toast.error(err.message || "Failed to change password");
    } finally {
      setLoading(false);
    }
  };

  if (!user) {
    return (
      <div className="flex items-center justify-center h-64">
        <Spinner size="lg" />
      </div>
    );
  }

  const initials = (user.full_name || user.username || user.email || "U")
    .split(" ")
    .map((n) => n[0])
    .join("")
    .toUpperCase()
    .slice(0, 2);

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {/* Profile header */}
      <Card className="border border-gray-200">
        <CardContent className="p-6 flex items-center gap-6">
          <div className="relative group">
            <div className="w-20 h-20 rounded-full bg-primary-100 flex items-center justify-center text-primary-700 text-2xl font-bold">
              {initials}
            </div>
            <button className="absolute inset-0 flex items-center justify-center bg-black bg-opacity-50 rounded-full opacity-0 group-hover:opacity-100 transition-opacity">
              <CameraIcon className="w-6 h-6 text-white" />
            </button>
          </div>
          <div>
            <h1 className="text-2xl font-bold text-gray-900">
              {user.full_name || user.username || "User"}
            </h1>
            <p className="text-sm text-gray-500 mt-1">{user.email}</p>
            <Badge variant="info" size="sm" className="mt-2">
              Member since {formatToIST(user.created_at, { day: undefined, hour: undefined, minute: undefined })}
            </Badge>
          </div>
        </CardContent>
      </Card>

      {/* Profile information */}
      <Card className="border border-gray-200">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <UserIcon className="w-5 h-5 text-primary-600" />
            Profile Information
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleProfileSubmit} className="space-y-4">
            <Input
              label="Full Name"
              name="full_name"
              value={form.full_name}
              onChange={handleChange}
              placeholder="Your full name"
              icon={<UserIcon className="w-5 h-5 text-gray-400" />}
            />
            <Input
              label="Username"
              name="username"
              value={form.username}
              onChange={handleChange}
              placeholder="Username"
              icon={<AtSymbolIcon className="w-5 h-5 text-gray-400" />}
            />
            <Input
              label="Email Address"
              name="email"
              type="email"
              value={form.email}
              onChange={handleChange}
              placeholder="email@example.com"
              icon={<MailIcon className="w-5 h-5 text-gray-400" />}
              disabled // email might be read-only
            />
            <div className="flex justify-end">
              <Button type="submit" variant="primary" disabled={loading}>
                {loading ? "Saving..." : "Save Changes"}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      {/* Security (password change) */}
      <Card className="border border-gray-200">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <LockClosedIcon className="w-5 h-5 text-primary-600" />
            Security
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handlePasswordSubmit} className="space-y-4">
            <Input
              label="Current Password"
              name="current_password"
              type="password"
              value={passwordForm.current_password}
              onChange={handlePasswordChange}
              placeholder="••••••••"
              icon={<LockClosedIcon className="w-5 h-5 text-gray-400" />}
              required
            />
            <Input
              label="New Password"
              name="new_password"
              type="password"
              value={passwordForm.new_password}
              onChange={handlePasswordChange}
              placeholder="At least 6 characters"
              icon={<LockClosedIcon className="w-5 h-5 text-gray-400" />}
              required
            />
            <Input
              label="Confirm New Password"
              name="confirm_password"
              type="password"
              value={passwordForm.confirm_password}
              onChange={handlePasswordChange}
              placeholder="Re-enter new password"
              icon={<LockClosedIcon className="w-5 h-5 text-gray-400" />}
              required
              error={passwordError}
            />
            {passwordError && (
              <p className="text-sm text-danger-600">{passwordError}</p>
            )}
            <div className="flex justify-end">
              <Button type="submit" variant="primary" disabled={loading}>
                {loading ? "Updating..." : "Change Password"}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
