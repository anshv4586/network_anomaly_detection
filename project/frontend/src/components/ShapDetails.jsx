import React from 'react';
import { Info, HelpCircle } from 'lucide-react';

export default function ShapDetails({ explanation, textExplanation, attackType }) {
  if (!explanation || explanation.length === 0) {
    return (
      <div className="text-gray-500 italic text-center py-6 font-mono text-sm">
        No explainability data available for this selection.
      </div>
    );
  }

  // Find max absolute value to scale bars
  const maxImpact = Math.max(...explanation.map((item) => Math.abs(item.impact)), 0.01);

  return (
    <div className="space-y-6">
      {/* Natural Language Explanation Card */}
      <div className="bg-cyber-dark/50 border border-cyber-border rounded-xl p-4 flex items-start space-x-3 shadow-inner">
        <Info className="w-5 h-5 text-cyber-cyan shrink-0 mt-0.5" />
        <div>
          <h4 className="text-sm font-semibold text-white font-mono mb-1">DECISION VECTOR SUMMARY ({attackType})</h4>
          <p className="text-sm text-gray-300 leading-relaxed font-mono select-text">{textExplanation}</p>
        </div>
      </div>

      {/* Feature Contributions Chart */}
      <div className="space-y-4">
        <div className="flex items-center justify-between text-xs font-mono text-gray-400">
          <span>FEATURE VECTOR</span>
          <span className="flex items-center space-x-1">
            <span>BENIGN (-ve)</span>
            <span className="inline-block w-2 h-2 bg-cyber-green rounded-full mx-1"></span>
            <span>|</span>
            <span className="inline-block w-2 h-2 bg-cyber-red rounded-full mx-1"></span>
            <span>ATTACK (+ve)</span>
          </span>
        </div>

        <div className="space-y-3 font-mono">
          {explanation.map((item, idx) => {
            const isPositive = item.impact > 0;
            const percentage = Math.min((Math.abs(item.impact) / maxImpact) * 100, 100);
            
            return (
              <div key={idx} className="space-y-1 hover:bg-gray-800/20 p-1.5 rounded transition-all duration-300">
                <div className="flex justify-between items-center text-xs">
                  <span className="text-white font-semibold">{item.display_name || item.feature}</span>
                  <span className={`font-semibold ${isPositive ? 'text-cyber-red' : 'text-cyber-green'}`}>
                    {isPositive ? '+' : ''}{item.impact.toFixed(4)}
                  </span>
                </div>
                
                {/* Horizontal Bar */}
                <div className="h-2.5 w-full bg-gray-800 rounded-full overflow-hidden flex relative">
                  {/* Center line divider */}
                  <div className="absolute left-1/2 top-0 bottom-0 w-0.5 bg-gray-600/30 z-10"></div>
                  
                  {isPositive ? (
                    // Bar growing right from the center (50%)
                    <div 
                      className="h-full bg-gradient-to-r from-cyber-red/60 to-cyber-red rounded-r shadow-glow-red absolute" 
                      style={{ 
                        left: '50%', 
                        width: `${percentage / 2}%` 
                      }}
                    />
                  ) : (
                    // Bar growing left from the center (50%)
                    <div 
                      className="h-full bg-gradient-to-l from-cyber-green/60 to-cyber-green rounded-l shadow-glow-green absolute" 
                      style={{ 
                        right: '50%', 
                        width: `${percentage / 2}%` 
                      }}
                    />
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
