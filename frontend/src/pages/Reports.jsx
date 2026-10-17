import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { 
  EyeIcon, 
  TrashIcon, 
  RefreshIcon, 
  ChevronDownIcon, 
  ChevronUpIcon,
  ShieldCheckIcon,
  ExclamationCircleIcon,
  DocumentDownloadIcon,
  TerminalIcon
} from '@heroicons/react/outline';
import api from '../api';
import toast from 'react-hot-toast';
import LiveLogs from '../components/LiveLogs';
import ScanTypeBadge from '../components/ScanTypeBadge';
import { formatToIST } from '../utils/date';

export default function Reports() {
  const [groups, setGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [expandedGroup, setExpandedGroup] = useState(null);
  const [groupScans, setGroupScans] = useState({});
  const [showLiveFeed, setShowLiveFeed] = useState({});
  const [scannerIp, setScannerIp] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 5;

  useEffect(() => {
    fetchGroups();
    fetchScannerIp();
  }, []);

  const fetchScannerIp = async () => {
    try {
      const res = await api.get('/dashboard/stats');
      setScannerIp(res.data?.health?.scanner_ip);
    } catch (err) {
      console.error("Failed to fetch scanner IP", err);
    }
  };

  const fetchGroups = async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);
    
    try {
      const res = await api.get('/scan_groups');
      setGroups(res.data);
    } catch (err) {
      console.error(err);
      toast.error('Failed to fetch campaigns');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const fetchGroupScans = async (groupId) => {
    try {
      const res = await api.get(`/scan_groups/${groupId}/scans`);
      setGroupScans(prev => ({ ...prev, [groupId]: res.data }));
    } catch (err) {
      console.error(err);
      toast.error('Failed to fetch scans for this campaign');
    }
  };

  const toggleGroup = (groupId) => {
    if (expandedGroup === groupId) {
      setExpandedGroup(null);
    } else {
      setExpandedGroup(groupId);
      fetchGroupScans(groupId);
    }
  };

  const toggleLiveFeed = (e, groupId) => {
    e.stopPropagation();
    setShowLiveFeed(prev => ({ ...prev, [groupId]: !prev[groupId] }));
  };

  const handleDeleteScan = async (e, groupId, scanId) => {
    e.stopPropagation();
    if (!window.confirm('Are you sure you want to delete this scan?')) return;
    
    try {
      await api.delete(`/scan_groups/${groupId}/scans/${scanId}`);
      toast.success('Scan deleted');
      // Refresh the scans for this group
      fetchGroupScans(groupId);
      // Also refresh groups to update counts
      fetchGroups(true);
    } catch (err) {
      console.error(err);
      toast.error('Failed to delete scan');
    }
  };

  const handleDeleteGroup = async (e, groupId) => {
    e.stopPropagation();
    if (!window.confirm('Are you sure you want to delete this whole campaign and all its scans?')) return;
    
    try {
      await api.delete(`/scan_groups/${groupId}`);
      toast.success('Campaign deleted');
      fetchGroups(true);
      if (expandedGroup === groupId) {
        setExpandedGroup(null);
      }
    } catch (err) {
      console.error(err);
      toast.error('Failed to delete campaign');
    }
  };

  const handleDownloadReport = async (e, groupId, campaignName) => {
    e.stopPropagation();
    const loadingToast = toast.loading('Generating campaign report...');
    try {
      const response = await api.get(`/scan_groups/${groupId}/report`);
      // Since our api.get wrapper returns the raw response for non-JSON, we must call .blob()
      const blob = await response.data.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `campaign_${campaignName.replace(/\s+/g, '_')}_report.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      toast.success('Report downloaded successfully', { id: loadingToast });
    } catch (err) {
      console.error(err);
      toast.error('Failed to generate report', { id: loadingToast });
    }
  };

  if (loading) return (
    <div className="flex items-center justify-center min-h-[400px]">
      <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
    </div>
  );

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 tracking-tight">Scan Campaigns</h1>
          <p className="text-gray-500 mt-1">Manage and view security assessment results</p>
        </div>
        <div className="flex items-center space-x-3">
          <button 
            onClick={() => fetchGroups(true)} 
            disabled={refreshing}
            className="p-2 text-gray-500 hover:text-indigo-600 hover:bg-indigo-50 rounded-full transition-all duration-200"
            title="Refresh"
          >
            <RefreshIcon className={`h-6 w-6 ${refreshing ? 'animate-spin' : ''}`} />
          </button>
          <Link to="/scan" className="px-5 py-2.5 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 shadow-sm transition-all duration-200 font-medium">
            New Campaign
          </Link>
        </div>
      </div>

      <div className="space-y-4">
        {groups.length === 0 ? (
          <div className="text-center py-20 bg-white rounded-xl shadow-sm border border-gray-100">
            <ShieldCheckIcon className="h-16 w-16 text-gray-300 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900">No campaigns found</h3>
            <p className="text-gray-500 mt-1">Start by creating your first security scan campaign</p>
            <Link to="/scan" className="text-indigo-600 font-medium mt-4 inline-block hover:underline">Create Campaign</Link>
          </div>
        ) : (
          <>
            {groups.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage).map(group => (
              <div key={group.id} className="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden hover:shadow-md transition-shadow duration-200">
                <div 
                  className="p-5 flex justify-between items-center cursor-pointer select-none bg-white hover:bg-gray-50 transition-colors duration-150" 
                  onClick={() => toggleGroup(group.id)}
                >
                  <div className="flex-1">
                    <div className="flex items-center space-x-3">
                      <h2 className="text-xl font-bold text-gray-800">{group.name}</h2>
                      <span className="text-xs text-gray-400 font-normal">Created {formatToIST(group.created_at, { hour: undefined, minute: undefined })}</span>
                    </div>
                    
                    {scannerIp && (
                      <div className="mt-1 flex">
                        <div className="px-2 py-0.5 bg-indigo-50 text-indigo-700 border border-indigo-100 rounded-full text-[9px] font-black uppercase tracking-widest flex items-center gap-1 shadow-sm">
                          <span className="w-1 h-1 bg-indigo-500 rounded-full animate-pulse"></span>
                          Checks performed by: {scannerIp}
                        </div>
                      </div>
                    )}
                    
                    {/* Engines utilized badges */}
                    <div className="flex flex-wrap gap-2 mt-2">
                      <ScanTypeBadge type={(group.engines || []).join(', ')} />
                      {(!group.engines || group.engines.length === 0) && <span className="text-xs text-gray-400 italic">No scans started</span>}
                    </div>
                    
                    {group.description && <p className="text-sm text-gray-500 mt-2 line-clamp-1">{group.description}</p>}
                  </div>
                  
                  <div className="flex items-center space-x-8">
                    <div className="text-center">
                      <div className="text-2xl font-bold text-gray-900">{group.scan_count}</div>
                      <div className="text-[10px] text-gray-400 uppercase font-bold tracking-widest">Scans</div>
                    </div>
                    
                    <div className="text-center min-w-[100px]">
                      <div className={`text-2xl font-bold ${group.avg_compliance > 80 ? 'text-green-600' : group.avg_compliance > 50 ? 'text-yellow-600' : 'text-red-600'}`}>
                        {group.avg_compliance}%
                      </div>
                      <div className="text-[10px] text-gray-400 uppercase font-bold tracking-widest">Compliance</div>
                    </div>
                    
                    <div className="flex items-center space-x-4">
                      {group.scan_count > 0 && (
                        <button 
                          onClick={(e) => handleDownloadReport(e, group.id, group.name)}
                          className="p-1.5 text-gray-400 hover:text-green-600 hover:bg-green-50 rounded-md transition-all duration-200"
                          title="Download Campaign Report"
                        >
                          <DocumentDownloadIcon className="h-5 w-5" />
                        </button>
                      )}
                      <button 
                        onClick={(e) => handleDeleteGroup(e, group.id)}
                        className="p-1.5 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-md transition-all duration-200"
                        title="Delete Campaign"
                      >
                        <TrashIcon className="h-5 w-5" />
                      </button>
                      <div className="text-gray-400">
                        {expandedGroup === group.id ? <ChevronUpIcon className="h-6 w-6" /> : <ChevronDownIcon className="h-6 w-6" />}
                      </div>
                    </div>
                  </div>
                </div>
                
                {expandedGroup === group.id && (
                  <div className="px-5 pb-5 pt-0 border-t border-gray-50">
                    <div className="flex justify-end mt-4">
                      <button 
                        onClick={(e) => toggleLiveFeed(e, group.id)}
                        className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-bold transition-all ${
                          showLiveFeed[group.id] 
                            ? 'bg-gray-800 text-white shadow-inner' 
                            : 'bg-indigo-50 text-indigo-700 hover:bg-indigo-100 border border-indigo-100'
                        }`}
                      >
                        <TerminalIcon className="h-4 w-4" />
                        {showLiveFeed[group.id] ? 'Hide Live Feed' : 'Show Campaign Live Feed'}
                      </button>
                    </div>

                    {showLiveFeed[group.id] && (
                      <div className="mt-4 mb-6">
                        <LiveLogs groupId={group.id} status={group.scan_count > 0 ? 'RUNNING' : 'IDLE'} />
                      </div>
                    )}

                    {group.scan_count === 0 ? (
                      <div className="py-6 text-center">
                        <p className="text-gray-400 text-sm italic">No scans have been initiated for this campaign yet.</p>
                        <Link to={`/scan?group=${group.id}`} className="text-indigo-600 text-sm font-medium mt-2 inline-block hover:underline">Add scans now</Link>
                      </div>
                    ) : (
                      <div className="overflow-hidden rounded-lg border border-gray-100 mt-4">
                        <table className="min-w-full divide-y divide-gray-200">
                          <thead className="bg-gray-50">
                            <tr>
                              <th className="px-4 py-3 text-left text-[10px] font-bold text-gray-400 uppercase tracking-wider">Target</th>
                              <th className="px-4 py-3 text-left text-[10px] font-bold text-gray-400 uppercase tracking-wider">Port</th>
                              <th className="px-4 py-3 text-left text-[10px] font-bold text-gray-400 uppercase tracking-wider">Engine</th>
                              <th className="px-4 py-3 text-left text-[10px] font-bold text-gray-400 uppercase tracking-wider">Executed At</th>
                              <th className="px-4 py-3 text-left text-[10px] font-bold text-gray-400 uppercase tracking-wider">Status</th>
                              <th className="px-4 py-3 text-left text-[10px] font-bold text-gray-400 uppercase tracking-wider">Compliance</th>
                              <th className="px-4 py-3 text-right text-[10px] font-bold text-gray-400 uppercase tracking-wider">Actions</th>
                            </tr>
                          </thead>
                          <tbody className="bg-white divide-y divide-gray-100">
                            {(groupScans[group.id] || []).map(scan => (
                              <tr key={scan.id} className="hover:bg-gray-50 transition-colors duration-150">
                                <td className="px-4 py-3 text-sm font-medium text-gray-900">
                                  {scan.domain}
                                </td>
                                <td className="px-4 py-3">
                                  {scan.scan_metadata?.port ? (
                                    <span className="px-2 py-0.5 bg-primary-50 text-primary-700 rounded text-[10px] font-black border border-primary-100 uppercase tracking-tight">
                                      {scan.scan_metadata.port}
                                    </span>
                                  ) : (
                                    <span className="text-gray-300 text-xs italic">---</span>
                                  )}
                                </td>
                                <td className="px-4 py-3 text-sm">
                                  <ScanTypeBadge type={scan.scan_type} />
                                </td>
                                <td className="px-4 py-3 text-xs text-gray-500">
                                  {formatToIST(scan.created_at)}
                                </td>
                                <td className="px-4 py-3">
                                  <span className={`px-2 py-1 text-[10px] font-bold rounded-full ${
                                    scan.status === 'COMPLETED' ? 'bg-green-100 text-green-700' : 
                                    scan.status === 'RUNNING' ? 'bg-blue-100 text-blue-700 animate-pulse' : 
                                    scan.status === 'PENDING' ? 'bg-gray-100 text-gray-700' :
                                    'bg-red-100 text-red-700'
                                  }`}>
                                    {scan.status}
                                  </span>
                                </td>
                                <td className="px-4 py-3">
                                  {scan.status === 'COMPLETED' ? (
                                    <span className={`text-xs font-bold ${scan.compliance_percent > 80 ? 'text-green-600' : scan.compliance_percent > 50 ? 'text-yellow-600' : 'text-red-600'}`}>
                                      {scan.compliance_percent}%
                                    </span>
                                  ) : <span className="text-gray-300 text-xs italic">N/A</span>}
                                </td>
                                <td className="px-4 py-3 text-right">
                                  <div className="flex justify-end space-x-2">
                                    <Link 
                                      to={`/reports/${scan.id}`} 
                                      className="p-1.5 text-gray-400 hover:text-indigo-600 hover:bg-indigo-50 rounded-md transition-all duration-200"
                                      title="View Detailed Report"
                                    >
                                      <EyeIcon className="h-5 w-5" />
                                    </Link>
                                    <button 
                                      onClick={(e) => handleDeleteScan(e, group.id, scan.id)}
                                      className="p-1.5 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-md transition-all duration-200"
                                      title="Delete Scan"
                                    >
                                      <TrashIcon className="h-5 w-5" />
                                    </button>
                                  </div>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
            
            {/* Pagination Controls */}
            {groups.length > itemsPerPage && (
              <div className="flex items-center justify-between bg-white px-4 py-3 sm:px-6 rounded-xl border border-gray-100 shadow-sm mt-6">
                <div className="flex flex-1 justify-between sm:hidden">
                  <button
                    onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                    disabled={currentPage === 1}
                    className="relative inline-flex items-center rounded-md border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                  >
                    Previous
                  </button>
                  <button
                    onClick={() => setCurrentPage(p => Math.min(Math.ceil(groups.length / itemsPerPage), p + 1))}
                    disabled={currentPage === Math.ceil(groups.length / itemsPerPage)}
                    className="relative ml-3 inline-flex items-center rounded-md border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                  >
                    Next
                  </button>
                </div>
                <div className="hidden sm:flex sm:flex-1 sm:items-center sm:justify-between">
                  <div>
                    <p className="text-sm text-gray-700">
                      Showing <span className="font-medium">{(currentPage - 1) * itemsPerPage + 1}</span> to <span className="font-medium">{Math.min(currentPage * itemsPerPage, groups.length)}</span> of{' '}
                      <span className="font-medium">{groups.length}</span> campaigns
                    </p>
                  </div>
                  <div>
                    <nav className="isolate inline-flex -space-x-px rounded-md shadow-sm" aria-label="Pagination">
                      <button
                        onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                        disabled={currentPage === 1}
                        className="relative inline-flex items-center rounded-l-md px-2 py-2 text-gray-400 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0 disabled:opacity-50"
                      >
                        <span className="sr-only">Previous</span>
                        <ChevronDownIcon className="h-5 w-5 rotate-90" aria-hidden="true" />
                      </button>
                      
                      {[...Array(Math.ceil(groups.length / itemsPerPage)).keys()].map((n) => (
                        <button
                          key={n + 1}
                          onClick={() => setCurrentPage(n + 1)}
                          className={`relative inline-flex items-center px-4 py-2 text-sm font-semibold focus:z-20 focus:outline-offset-0 ${
                            currentPage === n + 1 
                              ? 'z-10 bg-indigo-600 text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600' 
                              : 'text-gray-900 ring-1 ring-inset ring-gray-300 hover:bg-gray-50'
                          }`}
                        >
                          {n + 1}
                        </button>
                      ))}

                      <button
                        onClick={() => setCurrentPage(p => Math.min(Math.ceil(groups.length / itemsPerPage), p + 1))}
                        disabled={currentPage === Math.ceil(groups.length / itemsPerPage)}
                        className="relative inline-flex items-center rounded-r-md px-2 py-2 text-gray-400 ring-1 ring-inset ring-gray-300 hover:bg-gray-50 focus:z-20 focus:outline-offset-0 disabled:opacity-50"
                      >
                        <span className="sr-only">Next</span>
                        <ChevronDownIcon className="h-5 w-5 -rotate-90" aria-hidden="true" />
                      </button>
                    </nav>
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
