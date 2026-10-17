import React, { useState, useEffect, useRef } from 'react';
import { TerminalIcon, RefreshIcon, XCircleIcon } from '@heroicons/react/outline';
import api, { BASE } from '../api';
import { formatTimeIST } from '../utils/date';

const STAGE_COLORS = {
  'INIT': 'text-blue-400',
  'START': 'text-green-400',
  'CHECK': 'text-indigo-400',
  'RESULT': 'text-yellow-400',
  'SUMMARY': 'text-purple-400',
  'DONE': 'text-green-500 font-bold',
  'ERROR': 'text-red-400',
  'CRITICAL': 'text-red-600 font-bold underline',
  'WORKER': 'text-gray-400 italic',
  'EXEC': 'text-cyan-400 font-bold',
  'OUTPUT': 'text-gray-300',
  'CACHE': 'text-cyan-800 italic',
  'TERMINAL': 'text-green-400 font-bold',
  'INFO': 'text-blue-300 italic'
};

export default function LiveLogs({ scanId, groupId, discoveryId, status }) {
  const [logs, setLogs] = useState([]);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState(null);
  const scrollRef = useRef(null);
  const wsRef = useRef(null);

  const isGroup = !!groupId;
  const isDiscovery = !!discoveryId;

  // Fetch initial logs
  useEffect(() => {
    const fetchInitialLogs = async () => {
      try {
        let url;
        if (isDiscovery) {
          // Discovery jobs don't have a persistent log table in DB like ScanLog
          // but they might have some initial results. For now, we rely on WS.
          return;
        } else if (isGroup) {
          url = `/scans/groups/${groupId}/logs`;
        } else {
          url = `/scans/${scanId}/logs`;
        }
        const res = await api.get(url);
        if (res.data) {
          setLogs(res.data);
        }
      } catch (err) {
        console.error("Failed to fetch initial logs:", err);
      }
    };
    fetchInitialLogs();
  }, [scanId, groupId, isGroup, isDiscovery, discoveryId]);

  // Connect to WebSocket
  useEffect(() => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    let host = window.location.host;
    let pathPrefix = BASE;

    if (BASE && BASE.startsWith('http')) {
      try {
        const url = new URL(BASE);
        host = url.host;
        pathPrefix = url.pathname;
      } catch (e) {
        console.error("Invalid BASE URL:", BASE);
      }
    }
    
    if (!pathPrefix || pathPrefix === '/') pathPrefix = '/api';
    if (!pathPrefix.startsWith('/')) pathPrefix = '/' + pathPrefix;
    if (pathPrefix.endsWith('/')) pathPrefix = pathPrefix.slice(0, -1);
    
    let wsFullUrl;
    if (isDiscovery) {
      wsFullUrl = `${protocol}//${host}${pathPrefix}/discovery-feed/${discoveryId}`;
    } else {
      const wsPath = isGroup ? `groups/${groupId}/ws` : `${scanId}/ws`;
      wsFullUrl = `${protocol}//${host}${pathPrefix}/scans/${wsPath}`;
    }
    
    console.log(`Connecting to WebSocket: ${wsFullUrl}`);
    
    const ws = new WebSocket(wsFullUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      setError(null);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.stage === 'PING') return;
        
        setLogs(prev => {
          // Check for duplicate IDs (if backend provides them)
          if (data.id && prev.some(l => l.id === data.id)) return prev;

          // ── SPECIAL LOGIC: Replace LIVE lines with TERMINAL block ──
          if (data.stage === 'TERMINAL') {
            const match = data.message.match(/^ID:\[(.*?)\]\n/);
            if (match) {
              const commandId = match[1];
              const cleanTerminalMsg = data.message.replace(/^ID:\[.*?\]\n/, "");
              
              // Filter out all LIVE lines belonging to this command
              const filtered = prev.filter(l => {
                if (l.stage !== 'LIVE') return true;
                return !l.message.startsWith(`[${commandId}]`);
              });
              
              return [...filtered, { ...data, message: cleanTerminalMsg }];
            }
          }
          
          return [...prev, data];
        });
      } catch (e) {
        console.error("Failed to parse WS message:", event.data);
      }
    };

    ws.onerror = (err) => {
      setError("Stream connection failed.");
      setConnected(false);
    };

    ws.onclose = () => {
      setConnected(false);
    };

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [scanId, groupId, isGroup, status]);

  // Auto-scroll to bottom
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  const clearLogs = () => setLogs([]);

  const renderLogMessage = (log) => {
    // Strip identifier from LIVE messages for display
    if (log.stage === 'LIVE') {
      return log.message.replace(/^\[.*?\]\s/, "");
    }
    return log.message;
  };

  return (
    <div className="bg-gray-900 rounded-lg shadow-xl overflow-hidden border border-gray-700 flex flex-col h-[600px]">
      {/* Terminal Header */}
      <div className="bg-gray-800 px-4 py-2 flex justify-between items-center border-b border-gray-700">
        <div className="flex items-center gap-2">
          <TerminalIcon className="w-4 h-4 text-gray-400" />
          <span className="text-xs font-mono text-gray-300 uppercase tracking-widest">
            {isDiscovery ? 'Discovery Terminal' : isGroup ? 'Real-time Campaign Stream' : 'Real-time Scan Stream'}
          </span>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <div className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500 animate-pulse' : 'bg-gray-500'}`}></div>
            <span className="text-[10px] text-gray-400 uppercase font-bold">{connected ? 'Live' : 'Offline'}</span>
          </div>
          <button onClick={clearLogs} className="text-gray-500 hover:text-gray-300">
            <RefreshIcon className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Terminal Body */}
      <div 
        ref={scrollRef}
        className="flex-1 p-4 font-mono text-[13px] overflow-y-auto custom-scrollbar text-left"
      >
        {logs.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-gray-600 italic">
            <p>Initializing stream...</p>
          </div>
        ) : (
          <div className="flex flex-col">
            {logs.map((log, idx) => {
              if (log.stage === 'TERMINAL') {
                return (
                  <div key={idx} className="my-4 p-4 bg-black/40 border border-gray-800 rounded text-gray-100 whitespace-pre overflow-x-auto shadow-inner">
                    {renderLogMessage(log)}
                  </div>
                );
              }

              if (log.stage === 'LIVE') {
                return (
                  <div key={idx} className="flex gap-2 items-baseline leading-relaxed py-[1px]">
                    {isGroup && (
                      <span className="text-[10px] text-cyan-700 shrink-0 min-w-[30px]">#{log.scan_id}</span>
                    )}
                    <span className="text-gray-300 whitespace-pre-wrap break-all">{renderLogMessage(log)}</span>
                  </div>
                );
              }

              return (
                <div key={idx} className="flex gap-3 items-baseline leading-relaxed py-0.5 border-b border-gray-800/20">
                  <span className="text-[10px] text-gray-600 shrink-0 font-mono">
                    [{formatTimeIST(log.created_at || log.timestamp)}]
                  </span>
                  {isGroup && (
                    <span className="text-[10px] text-cyan-600 font-bold shrink-0 min-w-[30px]">#{log.scan_id}</span>
                  )}
                  <span className={`shrink-0 min-w-[65px] text-[10px] font-bold uppercase tracking-tighter ${STAGE_COLORS[log.stage] || 'text-gray-300'}`}>
                    {log.stage}
                  </span>
                  <span className="text-gray-100 break-all">{renderLogMessage(log)}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="bg-gray-800/50 px-4 py-1.5 border-t border-gray-700 flex justify-between">
        <p className="text-[10px] text-gray-500 italic">
          {connected ? 'Connection established. Streaming line-by-line.' : 'Reconnecting to stream...'}
        </p>
        {isGroup && <p className="text-[10px] text-gray-500 uppercase tracking-widest font-bold">Multitasking Enabled</p>}
      </div>

      <style jsx>{`
        .custom-scrollbar::-webkit-scrollbar { width: 6px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: #0f172a; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #475569; }
      `}</style>
    </div>
  );
}
