// src/layout/Topbar.jsx
import { useLocation, Link, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { Menu, Transition } from "@headlessui/react";
import { Fragment } from "react";
import {
  ChevronDownIcon,
  LogoutIcon,
  UserIcon,
  ChevronRightIcon,
  HomeIcon,
  ArrowLeftIcon,
} from "@heroicons/react/outline";
import { cn } from "../utils/cn";

const BREADCRUMB_MAP = {
  "dashboard": "Dashboard",
  "scan": "Scan",
  "manual-scan": "Manual Scan",
  "reports": "Reports",
  "schedules": "Schedules",
  "new": "New",
  "edit": "Edit",
  "compare": "Compare Scans",
  "profile": "Profile",
  "admin": "Admin",
  "users": "Users",
};

export default function Topbar() {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  
  const pathnames = location.pathname.split("/").filter((x) => x);

  const initials = user
    ? (user.full_name || user.username || user.email || "U")
        .split(" ")
        .map((n) => n[0])
        .join("")
        .toUpperCase()
        .slice(0, 2)
    : "?";

  return (
    <header className="h-16 bg-white border-b border-gray-200 flex items-center justify-between px-6 flex-shrink-0">
      <div className="flex items-center space-x-4">
        {pathnames.length > 1 && (
          <button
            onClick={() => navigate(-1)}
            className="p-1.5 text-gray-400 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-all"
            title="Go Back"
          >
            <ArrowLeftIcon className="w-5 h-5" />
          </button>
        )}
        
        <nav className="flex items-center space-x-2 text-sm font-medium" aria-label="Breadcrumb">
          <Link 
            to="/dashboard" 
            className="text-gray-400 hover:text-gray-900 transition-colors flex items-center gap-1"
          >
            <HomeIcon className="w-4 h-4" />
            <span className="sr-only">Home</span>
          </Link>

          {pathnames.map((value, index) => {
            const last = index === pathnames.length - 1;
            const to = `/${pathnames.slice(0, index + 1).join("/")}`;
            
            // Custom labeling logic
            let label = BREADCRUMB_MAP[value] || value;
            if (pathnames[index - 1] === "reports" && !isNaN(value)) {
              label = `Report #${value}`;
            }

            return (
              <div key={to} className="flex items-center">
                <ChevronRightIcon className="w-4 h-4 text-gray-400 mx-1" />
                {last ? (
                  <span className="text-gray-900 font-bold capitalize">{label}</span>
                ) : (
                  <Link
                    to={to}
                    className="text-gray-400 hover:text-gray-900 transition-colors capitalize"
                  >
                    {label}
                  </Link>
                )}
              </div>
            );
          })}
        </nav>
      </div>

      <div className="flex items-center">
        <Menu as="div" className="relative">
          <Menu.Button className="flex items-center gap-3 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 rounded-lg px-3 py-2">
            <div className="w-8 h-8 rounded-full bg-primary-100 flex items-center justify-center text-primary-700 font-semibold">
              {initials}
            </div>
            <span className="hidden sm:block text-gray-700 font-medium">
              {user?.full_name || user?.username || "User"}
            </span>
            <ChevronDownIcon className="w-4 h-4 text-gray-500" />
          </Menu.Button>

          <Transition
            as={Fragment}
            enter="transition ease-out duration-100"
            enterFrom="transform opacity-0 scale-95"
            enterTo="transform opacity-100 scale-100"
            leave="transition ease-in duration-75"
            leaveFrom="transform opacity-100 scale-100"
            leaveTo="transform opacity-0 scale-95"
          >
            <Menu.Items className="absolute right-0 mt-2 w-48 origin-top-right bg-white divide-y divide-gray-100 rounded-lg shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none z-50">
              <div className="px-1 py-1">
                <Menu.Item>
                  {({ active }) => (
                    <Link
                      to="/profile"
                      className={cn(
                        "group flex w-full items-center rounded-md px-2 py-2 text-sm",
                        active ? "bg-gray-100 text-gray-900" : "text-gray-700"
                      )}
                    >
                      <UserIcon
                        className={cn(
                          "mr-2 h-5 w-5",
                          active ? "text-gray-500" : "text-gray-400"
                        )}
                      />
                      Profile
                    </Link>
                  )}
                </Menu.Item>

                <Menu.Item>
                  {({ active }) => (
                    <button
                      onClick={() => logout()}
                      className={cn(
                        "group flex w-full items-center rounded-md px-2 py-2 text-sm",
                        active ? "bg-danger-50 text-danger-900" : "text-gray-900"
                      )}
                    >
                      <LogoutIcon
                        className={cn(
                          "mr-2 h-5 w-5",
                          active ? "text-danger-500" : "text-gray-400"
                        )}
                      />
                      Logout
                    </button>
                  )}
                </Menu.Item>
              </div>
            </Menu.Items>
          </Transition>
        </Menu>
      </div>
    </header>
  );
}
