import React, { useState, useEffect } from 'react';
import { 
  UsersIcon, 
  ShieldCheckIcon, 
  LockClosedIcon, 
  GlobeAltIcon, 
  PencilIcon, 
  TrashIcon, 
  CheckIcon, 
  XIcon,
  SearchIcon,
  RefreshIcon,
  EyeIcon
} from '@heroicons/react/outline';
import { toast } from 'react-hot-toast';
import api from '../api';
import { Card } from '../components/ui/Card';
import Button from '../components/ui/Button';
import { useAuth } from '../auth/AuthContext';

export default function UserManagement() {
  const { impersonateUser } = useAuth();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [editingUser, setEditingUser] = useState(null);
  const [searchTerm, setSearchByTerm] = useState('');

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const res = await api.get('/users');
      setUsers(res.data);
    } catch (err) {
      toast.error('Failed to load users');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleUpdatePermissions = async (user) => {
    try {
      const res = await api.put(`/users/${user.id}`, {
        is_admin: user.is_admin,
        all_access: user.all_access,
        allowed_targets: user.allowed_targets,
        full_name: user.full_name,
        username: user.username
      });
      toast.success(`Updated ${user.email}`);
      setEditingUser(null);
      fetchUsers();
    } catch (err) {
      toast.error('Failed to update user');
    }
  };

  const handleDeleteUser = async (id) => {
    if (!window.confirm('Are you sure you want to delete this user?')) return;
    try {
      await api.delete(`/users/${id}`);
      toast.success('User deleted');
      fetchUsers();
    } catch (err) {
      toast.error('Failed to delete user');
    }
  };

  const handleImpersonate = (user) => {
    impersonateUser(user);
    toast.success(`Now viewing as ${user.email}`);
  };

  const filteredUsers = users.filter(u => 
    u.email.toLowerCase().includes(searchTerm.toLowerCase()) || 
    (u.full_name && u.full_name.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  return (
    <div className="space-y-6 max-w-7xl mx-auto px-4 py-8">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-extrabold text-gray-900 tracking-tight">User Management</h1>
          <p className="text-gray-500 text-sm mt-1">Manage user roles, permissions, and target restrictions</p>
        </div>
        
        <div className="relative">
          <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-gray-400">
            <SearchIcon className="h-5 w-5" />
          </span>
          <input
            type="text"
            placeholder="Search users..."
            className="pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500 w-full md:w-64"
            value={searchTerm}
            onChange={(e) => setSearchByTerm(e.target.value)}
          />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6">
        {loading ? (
          <div className="flex justify-center py-20">
            <RefreshIcon className="w-10 h-10 text-indigo-600 animate-spin" />
          </div>
        ) : (
          <Card padding={false} className="overflow-hidden">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">User</th>
                    <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Role</th>
                    <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Access</th>
                    <th className="px-6 py-3 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Allowed Targets</th>
                    <th className="px-6 py-3 text-right text-xs font-bold text-gray-500 uppercase tracking-wider">Actions</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {filteredUsers.map((user) => (
                    <tr key={user.id} className="hover:bg-gray-50 transition-colors">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          <div className="h-10 w-10 flex-shrink-0 rounded-full bg-indigo-100 flex items-center justify-center text-indigo-700 font-bold">
                            {user.email[0].toUpperCase()}
                          </div>
                          <div className="ml-4">
                            <div className="text-sm font-bold text-gray-900">{user.full_name || user.username || 'No Name'}</div>
                            <div className="text-xs text-gray-500">{user.email}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {editingUser?.id === user.id ? (
                          <select 
                            className="text-xs border rounded p-1"
                            value={editingUser.is_admin ? 'admin' : 'user'}
                            onChange={(e) => setEditingUser({...editingUser, is_admin: e.target.value === 'admin'})}
                          >
                            <option value="user">User</option>
                            <option value="admin">Admin</option>
                          </select>
                        ) : (
                          <span className={`px-2 py-1 text-[10px] font-black rounded-full uppercase tracking-tighter ${
                            user.is_admin ? 'bg-purple-100 text-purple-700 border border-purple-200' : 'bg-gray-100 text-gray-600 border border-gray-200'
                          }`}>
                            {user.is_admin ? 'Administrator' : 'Standard User'}
                          </span>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {editingUser?.id === user.id ? (
                          <div className="flex items-center gap-2">
                            <input 
                              type="checkbox" 
                              id={`all-access-${user.id}`}
                              checked={editingUser.all_access}
                              onChange={(e) => setEditingUser({...editingUser, all_access: e.target.checked})}
                              className="rounded text-indigo-600 focus:ring-indigo-500"
                            />
                            <label htmlFor={`all-access-${user.id}`} className="text-xs font-bold text-gray-700">All Access</label>
                          </div>
                        ) : (
                          <div className="flex items-center gap-1">
                            {user.is_admin || user.all_access ? (
                              <>
                                <GlobeAltIcon className="w-4 h-4 text-green-500" />
                                <span className="text-xs font-medium text-gray-700">Unrestricted</span>
                              </>
                            ) : (
                              <>
                                <LockClosedIcon className="w-4 h-4 text-amber-500" />
                                <span className="text-xs font-medium text-gray-700">Restricted</span>
                              </>
                            )}
                          </div>
                        )}
                      </td>
                      <td className="px-6 py-4">
                        {editingUser?.id === user.id ? (
                          <textarea
                            className="w-full text-xs border rounded p-2 focus:ring-indigo-500 focus:border-indigo-500"
                            placeholder="e.g. google.com, 1.2.3.4, example.org"
                            value={editingUser.allowed_targets || ''}
                            onChange={(e) => setEditingUser({...editingUser, allowed_targets: e.target.value})}
                            disabled={editingUser.all_access}
                            rows={2}
                          />
                        ) : (
                          <div className="max-w-xs overflow-hidden text-ellipsis">
                            <p className="text-xs text-gray-600 italic">
                              {user.is_admin || user.all_access ? 'All Allowed' : user.allowed_targets || 'None assigned'}
                            </p>
                          </div>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                        {editingUser?.id === user.id ? (
                          <div className="flex justify-end gap-2">
                            <button 
                              onClick={() => handleUpdatePermissions(editingUser)}
                              className="p-1 text-green-600 hover:bg-green-50 rounded transition-colors"
                              title="Save"
                            >
                              <CheckIcon className="w-5 h-5" />
                            </button>
                            <button 
                              onClick={() => setEditingUser(null)}
                              className="p-1 text-red-600 hover:bg-red-50 rounded transition-colors"
                              title="Cancel"
                            >
                              <XIcon className="w-5 h-5" />
                            </button>
                          </div>
                        ) : (
                          <div className="flex justify-end gap-2">
                            {!user.is_admin && (
                              <button 
                                onClick={() => handleImpersonate(user)}
                                className="p-1 text-blue-600 hover:bg-blue-50 rounded transition-colors"
                                title="View as User (Impersonate)"
                              >
                                <EyeIcon className="w-5 h-5" />
                              </button>
                            )}
                            {!user.is_admin && (
                              <button 
                                onClick={() => setEditingUser({...user})}
                                className="p-1 text-indigo-600 hover:bg-indigo-50 rounded transition-colors"
                                title="Edit Permissions"
                              >
                                <PencilIcon className="w-5 h-5" />
                              </button>
                            )}
                            <button 
                              onClick={() => handleDeleteUser(user.id)}
                              className="p-1 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded transition-colors"
                              title="Delete User"
                            >
                              <TrashIcon className="w-5 h-5" />
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )}
      </div>
    </div>
  );
}
