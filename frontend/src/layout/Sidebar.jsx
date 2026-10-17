// src/layout/Sidebar.jsx
import { useState } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import {
  HomeIcon,
  DocumentTextIcon,
  PlusCircleIcon,
  CursorClickIcon,
  ScaleIcon,
  LogoutIcon,
  CalendarIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  UsersIcon,
  ViewGridIcon,
  ClipboardListIcon,
} from "@heroicons/react/outline";
import { EyeIcon } from "@heroicons/react/solid";
import { cn } from "../utils/cn";

const NAV = [
  { to: "/dashboard", label: "Dashboard", icon: HomeIcon },
  { to: "/scan", label: "Scan", icon: PlusCircleIcon },
  { to: "/manual-scan", label: "Manual Scan", icon: CursorClickIcon },
  { to: "/reports", label: "Reports", icon: DocumentTextIcon },
  { to: "/schedules", label: "Schedules", icon: CalendarIcon },
  { to: "/compare", label: "Compare", icon: ScaleIcon },
];

export default function Sidebar() {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const [collapsed, setCollapsed] = useState(false);

  const handleLogout = () => {
    logout();
    navigate("/login", { replace: true });
  };

  return (
    <aside
      className={cn(
        "flex-shrink-0 bg-white border-r border-gray-200 flex flex-col h-screen sticky top-0 transition-all duration-300 ease-in-out z-30",
        collapsed ? "w-20" : "w-64"
      )}
    >
      {/* Logo & Toggle */}
      <div className="h-16 flex items-center justify-between px-4 border-b border-gray-200 relative">
        <div className={cn("flex items-center gap-3 overflow-hidden", collapsed ? "w-10" : "w-auto")}>
          <div className="w-10 h-10 rounded-full bg-black flex-shrink-0 flex items-center justify-center shadow-md">
            <EyeIcon className="w-6 h-6 text-white" />
          </div>
          {!collapsed && (
            <span className="font-bold text-gray-900 text-xl tracking-tight whitespace-nowrap">
              M O C K  D R I L L
            </span>
          )}
        </div>
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="absolute -right-3 top-1/2 -translate-y-1/2 w-6 h-6 bg-white border border-gray-200 rounded-full flex items-center justify-center shadow-sm hover:bg-gray-50 text-gray-500 transition-colors"
        >
          {collapsed ? <ChevronRightIcon className="w-4 h-4" /> : <ChevronLeftIcon className="w-4 h-4" />}
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-5 space-y-2 overflow-y-auto overflow-x-hidden">
        {!collapsed && (
          <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-gray-400 px-3 mb-4">
            Main Menu
          </p>
        )}
        {NAV.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            title={collapsed ? label : ""}
            className={({ isActive }) =>
              cn(
                "group flex items-center gap-3 px-3 py-3 rounded-xl text-sm font-medium transition-all duration-200",
                collapsed ? "justify-center" : "justify-start",
                isActive
                  ? "bg-primary-50 text-primary-700 shadow-sm"
                  : "text-gray-500 hover:bg-gray-50 hover:text-gray-900"
              )
            }
          >
            {({ isActive }) => (
              <>
                <Icon className={cn(
                  "w-6 h-6 flex-shrink-0 transition-transform duration-200 group-hover:scale-110",
                  isActive ? "text-primary-600" : "text-gray-400 group-hover:text-primary-500"
                )} />
                {!collapsed && (
                  <span className="whitespace-nowrap transition-opacity duration-300 opacity-100">
                    {label}
                  </span>
                )}
              </>
            )}
          </NavLink>
        ))}

        {user?.is_admin && (
          <div className="pt-4 mt-4 border-t border-gray-100">
            {!collapsed && (
              <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-gray-400 px-3 mb-4">
                Admin Menu
              </p>
            )}
            <NavLink
              to="/admin/dashboard"
              title={collapsed ? "Admin Dashboard" : ""}
              className={({ isActive }) =>
                cn(
                  "group flex items-center gap-3 px-3 py-3 rounded-xl text-sm font-medium transition-all duration-200 mb-2",
                  collapsed ? "justify-center" : "justify-start",
                  isActive
                    ? "bg-primary-50 text-primary-700 shadow-sm"
                    : "text-gray-500 hover:bg-gray-50 hover:text-gray-900"
                )
              }
            >
              {({ isActive }) => (
                <>
                  <ViewGridIcon className={cn(
                    "w-6 h-6 flex-shrink-0 transition-transform duration-200 group-hover:scale-110",
                    isActive ? "text-primary-600" : "text-gray-400 group-hover:text-primary-500"
                  )} />
                  {!collapsed && (
                    <span className="whitespace-nowrap transition-opacity duration-300 opacity-100">
                      Overview
                    </span>
                  )}
                </>
              )}
            </NavLink>
            <NavLink
              to="/admin/custom-checks"
              title={collapsed ? "Custom Checks" : ""}
              className={({ isActive }) =>
                cn(
                  "group flex items-center gap-3 px-3 py-3 rounded-xl text-sm font-medium transition-all duration-200 mb-2",
                  collapsed ? "justify-center" : "justify-start",
                  isActive
                    ? "bg-primary-50 text-primary-700 shadow-sm"
                    : "text-gray-500 hover:bg-gray-50 hover:text-gray-900"
                )
              }
            >
              {({ isActive }) => (
                <>
                  <ClipboardListIcon className={cn(
                    "w-6 h-6 flex-shrink-0 transition-transform duration-200 group-hover:scale-110",
                    isActive ? "text-primary-600" : "text-gray-400 group-hover:text-primary-500"
                  )} />
                  {!collapsed && (
                    <span className="whitespace-nowrap transition-opacity duration-300 opacity-100">
                      Custom Checks
                    </span>
                  )}
                </>
              )}
            </NavLink>
            <NavLink
              to="/users"
              title={collapsed ? "User Management" : ""}
              className={({ isActive }) =>
                cn(
                  "group flex items-center gap-3 px-3 py-3 rounded-xl text-sm font-medium transition-all duration-200",
                  collapsed ? "justify-center" : "justify-start",
                  isActive
                    ? "bg-primary-50 text-primary-700 shadow-sm"
                    : "text-gray-500 hover:bg-gray-50 hover:text-gray-900"
                )
              }
            >
              {({ isActive }) => (
                <>
                  <UsersIcon className={cn(
                    "w-6 h-6 flex-shrink-0 transition-transform duration-200 group-hover:scale-110",
                    isActive ? "text-primary-600" : "text-gray-400 group-hover:text-primary-500"
                  )} />
                  {!collapsed && (
                    <span className="whitespace-nowrap transition-opacity duration-300 opacity-100">
                      Users
                    </span>
                  )}
                </>
              )}
            </NavLink>
          </div>
        )}
      </nav>

      {/* Logout */}
      {user && (
        <div className="px-3 py-4 border-t border-gray-100 bg-gray-50/50">
          <button
            onClick={handleLogout}
            title={collapsed ? "Logout" : ""}
            className={cn(
              "group w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-gray-500 hover:bg-rose-50 hover:text-rose-600 transition-all duration-200",
              collapsed ? "justify-center" : "justify-start"
            )}
          >
            <LogoutIcon className="w-5 h-5 flex-shrink-0 group-hover:rotate-12" />
            {!collapsed && <span className="whitespace-nowrap">Logout</span>}
          </button>
        </div>
      )}
    </aside>
  );
}
