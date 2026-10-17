// FILE: src/auth/AuthContext.jsx
import React, { createContext, useState, useContext, useEffect } from 'react';
import { getMe, login as apiLogin, clearToken, saveToken } from '../api/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [realUser, setRealUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const checkAuth = async () => {
      const token = sessionStorage.getItem('token');
      const impersonationToken = sessionStorage.getItem('impersonation_token');
      if (token) {
        try {
          const data = await getMe();
          setUser(data);
          // If we have an impersonation token, we might need more logic, 
          // but for simple "View as", we can just swap the user object.
        } catch (error) {
          console.error('Auth check failed:', error);
          clearToken();
        }
      }
      setLoading(false);
    };
    checkAuth();
  }, []);

  const login = async (identifier, password, isAdmin = false) => {
    try {
      const data = await apiLogin(identifier, password, isAdmin);
      const { access_token } = data;
      saveToken(access_token);
      const userData = await getMe();
      setUser(userData);
      setRealUser(null);
      return { success: true };
    } catch (error) {
      console.error('Login failed:', error);
      return { success: false, error: error.message || 'Login failed' };
    }
  };

  const logout = () => {
    clearToken();
    setUser(null);
    setRealUser(null);
  };

  const impersonateUser = async (targetUser) => {
    // Save current admin as realUser
    setRealUser(user);
    sessionStorage.setItem("impersonation_id", targetUser.id);
    // In a real system, we might fetch a new token, but for now 
    // we'll just swap the local user object to "view" their data.
    // Note: API calls will still use the Admin token, so the backend 
    // must support "admin-acting-as-user" or the admin must have all_access.
    setUser({ ...targetUser, is_impersonated: true });
  };

  const stopImpersonating = () => {
    if (realUser) {
      setUser(realUser);
      setRealUser(null);
      sessionStorage.removeItem("impersonation_id");
    }
  };

  const refreshUser = async () => {
    try {
      const data = await getMe();
      if (!realUser) {
        setUser(data);
      }
      return data;
    } catch (error) {
      console.error('Failed to refresh user:', error);
      throw error;
    }
  };

  const value = {
    user,
    realUser,
    login,
    logout,
    impersonateUser,
    stopImpersonating,
    refreshUser,
    loading,
    isAuthenticated: !!user,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
