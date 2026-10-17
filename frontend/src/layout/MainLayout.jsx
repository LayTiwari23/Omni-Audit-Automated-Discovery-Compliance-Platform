// src/layout/MainLayout.jsx
import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";
import Topbar from "./Topbar";
import { useAuth } from "../auth/AuthContext";
import { XIcon } from "@heroicons/react/outline";

export default function MainLayout() {
  const { user, realUser, stopImpersonating } = useAuth();

  return (
    <div className="flex h-screen bg-gray-50 overflow-hidden">
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        {realUser && (
          <div className="bg-indigo-600 text-white px-6 py-2.5 flex items-center justify-between text-sm font-semibold shadow-md z-50">
            <div className="flex items-center gap-3">
              <div className="flex items-center justify-center bg-white/20 backdrop-blur-sm px-2 py-0.5 rounded-md border border-white/30">
                <span className="text-[10px] uppercase tracking-wider">Impersonation Mode</span>
              </div>
              <p>
                Viewing platform as <span className="text-indigo-100 italic">{user.email}</span>
              </p>
            </div>
            <button 
              onClick={stopImpersonating}
              className="flex items-center gap-2 bg-white/10 hover:bg-white/20 px-3 py-1 rounded-lg transition-all border border-white/20 active:scale-95 shadow-sm"
            >
              Exit View Mode <XIcon className="w-4 h-4" />
            </button>
          </div>
        )}
        <Topbar />
        <main className="flex-1 overflow-y-auto p-6 lg:p-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
