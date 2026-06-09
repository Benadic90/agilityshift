import React from 'react';

function ReadinessScore({ score }) {
  let colorClass = 'text-green-500';
  let ringClass = 'border-green-500/30';
  
  if (score <= 40) {
    colorClass = 'text-critical';
    ringClass = 'border-critical/30';
  } else if (score <= 70) {
    colorClass = 'text-high';
    ringClass = 'border-high/30';
  }

  return (
    <div className="flex flex-col items-center">
      <h3 className="text-slate-400 text-sm uppercase tracking-wider mb-6">Migration Readiness</h3>
      <div className={`w-40 h-40 rounded-full border-[12px] ${ringClass} flex items-center justify-center`}>
        <div className="text-center">
          <span className={`text-4xl font-bold ${colorClass}`}>{score}</span>
          <span className="text-slate-400 text-xl font-medium">/100</span>
        </div>
      </div>
    </div>
  );
}

export default ReadinessScore;
