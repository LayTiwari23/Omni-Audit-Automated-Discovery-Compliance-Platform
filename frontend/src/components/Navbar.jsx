// src/components/Navbar.jsx
import React, { Fragment } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { Menu, Transition } from '@headlessui/react';
import { ShieldCheckIcon } from '@heroicons/react/solid';
import {
  HomeIcon,
  DocumentTextIcon,
  PlusCircleIcon,
  ChartBarIcon,
  ChevronDownIcon,
  LogoutIcon,
  UserCircleIcon,
} from '@heroicons/react/outline';
import { cn } from '../utils/cn';

const Navbar = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { logout, user } = useAuth();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const isActive = (path) => {
    if (path === '/reports') {
      return location.pathname === '/reports' || location.pathname.startsWith('/reports/');
    }
    return location.pathname === path;
  };

  const navLinkClass = (path) => {
    return cn(
      'inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium transition-colors',
      isActive(path)
        ? 'border-primary-600 text-gray-900'
        : 'border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700'
    );
  };

  const mobileLinkClass = (path) => {
    return cn(
      'block pl-3 pr-4 py-2 border-l-4 text-base font-medium transition-colors',
      isActive(path)
        ? 'bg-primary-50 border-primary-600 text-primary-700'
        : 'border-transparent text-gray-500 hover:bg-gray-50 hover:border-gray-300 hover:text-gray-700'
    );
  };

  const navigation = [
    { name: 'Dashboard', href: '/dashboard', icon: HomeIcon },
    { name: 'Reports', href: '/reports', icon: DocumentTextIcon },
    { name: 'Scan', href: '/scan', icon: PlusCircleIcon },
    { name: 'Compare', href: '/compare', icon: ChartBarIcon },
  ];

  return (
    <nav className="bg-white shadow-lg sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16">
          {/* Logo */}
          <div className="flex items-center">
            <Link to="/dashboard" className="flex items-center space-x-2 group">
              <ShieldCheckIcon className="w-8 h-8 text-primary-600 group-hover:text-primary-700 transition-colors" />
              <span className="text-xl font-bold text-gray-900 group-hover:text-primary-600 transition-colors">
                Mock Drill
              </span>
            </Link>
          </div>

          {/* Desktop Navigation */}
          <div className="hidden sm:flex sm:items-center sm:space-x-8">
            {navigation.map((item) => {
              const Icon = item.icon;
              return (
                <Link key={item.name} to={item.href} className={navLinkClass(item.href)}>
                  <Icon className="w-5 h-5 mr-1.5" />
                  {item.name}
                </Link>
              );
            })}
          </div>

          {/* User Menu */}
          <div className="flex items-center">
            <Menu as="div" className="relative">
              <Menu.Button className="flex items-center space-x-2 text-sm font-medium text-gray-700 hover:text-gray-900 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 rounded-md px-3 py-2">
                <UserCircleIcon className="w-6 h-6 text-primary-600" />
                <span>Admin</span>
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
                <Menu.Items className="absolute right-0 mt-2 w-48 origin-top-right bg-white divide-y divide-gray-100 rounded-lg shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none">
                  <div className="px-1 py-1">
                    <Menu.Item>
                      {({ active }) => (
                        <button
                          onClick={handleLogout}
                          className={cn(
                            'group flex w-full items-center rounded-md px-2 py-2 text-sm',
                            active ? 'bg-danger-50 text-danger-900' : 'text-gray-900'
                          )}
                        >
                          <LogoutIcon
                            className={cn(
                              'mr-2 h-5 w-5',
                              active ? 'text-danger-500' : 'text-gray-400'
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
        </div>
      </div>

      {/* Mobile menu */}
      <div className="sm:hidden border-t border-gray-200">
        <div className="pt-2 pb-3 space-y-1">
          {navigation.map((item) => {
            const Icon = item.icon;
            return (
              <Link key={item.name} to={item.href} className={mobileLinkClass(item.href)}>
                <div className="flex items-center">
                  <Icon className="w-5 h-5 mr-2" />
                  {item.name}
                </div>
              </Link>
            );
          })}
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
