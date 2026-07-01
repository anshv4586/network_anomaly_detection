import React, { useEffect, useRef } from 'react';
import { Terminal, RefreshCw, Trash2 } from 'lucide-react';

export default function ConsoleLogs({ logs, onRefresh }) {
  const containerRef = useRef(null);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div className="bg-cyber-card border border-cyber-border rounded-xl p-4 flex flex-col h-64 shadow-lg">
      <div className="flex items-center justify-between pb-3 border-b border-cyber-border mb-3">
        <div className="flex items-center space-x-2 text-sm font-semibold text-white font-mono">
          <Terminal className="w-4 h-4 text-cyber-cyan" />
          <span>REAL-TIME SYSTEM DIAGNOSTIC CONSOLE</span>
        </div>
        <button
          onClick={onRefresh}
          className="p-1.5 bg-gray-800 hover:bg-cyber-cyan/10 hover:text-cyber-cyan rounded-lg border border-gray-700 hover:border-cyber-cyan/30 text-gray-400 transition-all duration-300"
          title="Refresh Console Logs"
        >
          <RefreshCw className="w-3.5 h-3.5" />
        </button>
      </div>

      <div
        ref={containerRef}
        className="flex-1 overflow-y-auto font-mono text-xs space-y-1.5 pr-2 select-text"
      >
        {logs.length === 0 ? (
          <div className="text-gray-500 italic text-center pt-8">No diagnostics recorded.</div>
        ) : (
          logs.map((log) => {
            const isError = log.level === 'ERROR';
            const isWarning = log.level === 'WARNING';
            const levelColor = isError 
              ? 'text-cyber-red' 
              : (isWarning ? 'text-cyber-yellow' : 'text-cyber-cyan');
            
            return (
              <div key={log.id} className="flex items-start space-x-2 leading-relaxed hover:bg-gray-800/20 py-0.5 rounded px-1">
                <span className="text-gray-500 shrink-0">[{log.timestamp}]</span>
                <span className={`${levelColor} font-bold shrink-0`}>[{log.level}]</span>
                <span className="text-gray-300">{log.message}</span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
