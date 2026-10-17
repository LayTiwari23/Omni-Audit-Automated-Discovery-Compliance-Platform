/**
 * src/App.jsx
 *
 * Change from previous version: added /register public route.
 * All other routes, guards, and layout are unchanged.
 */
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider } from "./auth/AuthContext" ;
import MainLayout   from "./layout/MainLayout";
import Dashboard    from "./pages/Dashboard";
import Login        from "./pages/Login";
import Scan         from "./pages/Scan";
import ManualScan   from "./pages/ManualScan";
import Register     from "./pages/Register";
import ReportDetail from "./pages/ReportDetail";
import Reports      from "./pages/Reports";
import CompareScans from "./pages/CompareScans"; 
import Profile from "./pages/Profile";
import Schedules from "./pages/Schedules";
import ScheduleForm from "./pages/ScheduleForm";
import UserManagement from "./pages/UserManagement";
import AdminDashboard from "./pages/AdminDashboard";
import CustomChecks from "./pages/CustomChecks";
import { useAuth } from "./auth/AuthContext";

function RequireAuth({ children }) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return children;
}

function AdminRoute({ children }) {
  const { user, loading } = useAuth();
  
  if (loading) return null;
  if (!user || !user.is_admin) {
    return <Navigate to="/dashboard" replace />;
  }
  return children;
}

export default function App() {
  return (
    <BrowserRouter
  future={{
    v7_startTransition: true,
    v7_relativeSplatPath: true,
  }}
>
      <AuthProvider>
       <Routes>

        {/* ── Public routes (no auth required) ─────────────────────────── */}
        <Route path="/login"    element={<Login />} />
        <Route path="/register" element={<Register />} />

        {/* ── Protected routes (wrapped in sidebar + topbar layout) ──────── */}
        <Route
          path="/"
          element={
            <RequireAuth>
              <MainLayout />
            </RequireAuth>
          }
        >
          <Route index              element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard"   element={<Dashboard />} />
          <Route path="scan"        element={<Scan />} />
          <Route path="manual-scan" element={<ManualScan />} />
          <Route path="reports"     element={<Reports />} />
          <Route path="reports/:id" element={<ReportDetail />} />
          <Route path="schedules"   element={<Schedules />} />
          <Route path="schedules/new" element={<ScheduleForm />} />
          <Route path="schedules/:id/edit" element={<ScheduleForm />} />
          <Route path="compare"     element={<CompareScans />} />
          <Route path="/profile"    element={<Profile />} />
          <Route 
            path="/admin/dashboard" 
            element={
              <AdminRoute>
                <AdminDashboard />
              </AdminRoute>
            } 
          />
          <Route 
            path="/admin/custom-checks" 
            element={
              <AdminRoute>
                <CustomChecks />
              </AdminRoute>
            } 
          />
          <Route 
            path="/users" 
            element={
              <AdminRoute>
                <UserManagement />
              </AdminRoute>
            } 
          />
        </Route>

        {/* ── Catch-all ──────────────────────────────────────────────────── */}
        <Route path="*" element={<Navigate to="/dashboard" replace />} />

      </Routes>
     </AuthProvider>
    </BrowserRouter>
  );
}
