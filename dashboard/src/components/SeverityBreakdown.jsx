import React from 'react';

function SeverityBreakdown({ severitySummary }) {
  const severities = [
    { level: 'CRITICAL', count: severitySummary.CRITICAL || 0, bg: 'bg-critical/20', text: 'text-critical', border: 'border-critical' },
    { level: 'HIGH', count: severitySummary.HIGH || 0, bg: 'bg-high/20', text: 'text-high', border: 'border-high' },
    { level: 'MEDIUM', count: severitySummary.MEDIUM || 0, bg: 'bg-medium/20', text: 'text-medium', border: 'border-medium' },
    { level: 'LOW', count: severitySummary.LOW || 0, bg: 'bg-low/20', text: 'text-low', border: 'border-low' },
  ];

  return (
    <div>
      <h3 className="text-white font-medium mb-3">Severity Breakdown</h3>
      <div className="flex flex-wrap gap-3">
        {severities.map((sev) => (
          <div key={sev.level} className={`flex items-center px-4 py-2 rounded-full border ${sev.border} ${sev.bg} ${sev.text}`}>
            <span className="font-bold text-sm">{sev.level}: {sev.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default SeverityBreakdown;
