import React from 'react';
import { Shield, Radio, History, Settings, Cpu, HardDrive } from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab, systemStatus }) {
  const navItems = [
    { id: 'dashboard', name: 'Dashboard', icon: Cpu },
    { id: 'offline', name: 'Offline Mode', icon: HardDrive },
    { id: 'online', name: 'Online Sniffer', icon: Radio },
    { id: 'history', name: 'History Records', icon: History },
    { id: 'settings', name: 'Config Panel', icon: Settings },
  ];

  return (
    <header className="border-b border-cyber-border bg-cyber-dark/80 backdrop-blur-md sticky top-0 z-50 px-6 py-4 flex items-center justify-between">
      <div className="flex items-center space-x-3">
        <div className="p-2 bg-cyber-cyan/10 rounded-lg border border-cyber-cyan/30 shadow-[0_0_10px_rgba(6,182,212,0.1)]">
          <Shield className="w-6 h-6 text-cyber-cyan animate-pulse" />
        </div>
        <div>
          <h1 className="text-lg font-bold tracking-wider text-white">AEGIS-IDS</h1>
          <p className="text-xs text-cyber-cyan font-mono">Cybersecurity Intrusion Detection System</p>
        </div>
      </div>

      <nav className="flex space-x-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-300 ${
                isActive
                  ? 'bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/30 shadow-glow-cyan'
                  : 'text-gray-400 hover:text-white hover:bg-gray-800/50'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{item.name}</span>
            </button>
          );
        })}
      </nav>

      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-2 font-mono text-xs">
          <span className="text-gray-500">SYSTEM:</span>
          {systemStatus.is_running ? (
            <div className="flex items-center space-x-1.5 bg-cyber-green/10 border border-cyber-green/30 text-cyber-green px-2.5 py-1 rounded-full shadow-[0_0_8px_rgba(16,185,129,0.15)]">
              <span className="w-2 h-2 rounded-full bg-cyber-green animate-ping" />
              <span>RUNNING</span>
            </div>
          ) : (
            <div className="flex items-center space-x-1.5 bg-gray-800/80 border border-gray-700 text-gray-400 px-2.5 py-1 rounded-full">
              <span className="w-2 h-2 rounded-full bg-gray-500" />
              <span>STOPPED</span>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
