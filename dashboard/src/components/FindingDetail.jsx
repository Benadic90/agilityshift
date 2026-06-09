import React from 'react';

function FindingDetail({ finding }) {
  if (!finding) {
    return (
      <div className="flex items-center justify-center h-full text-slate-500">
        <p>Select a finding to view details.</p>
      </div>
    );
  }

  const getSeverityColor = (sev) => {
    switch(sev) {
      case 'CRITICAL': return 'bg-critical/20 text-critical border-critical';
      case 'HIGH': return 'bg-high/20 text-high border-high';
      case 'MEDIUM': return 'bg-medium/20 text-medium border-medium';
      case 'LOW': return 'bg-low/20 text-low border-low';
      default: return 'bg-slate-800 text-slate-300 border-slate-600';
    }
  };

  return (
    <div className="p-6 flex flex-col gap-6">
      <div className="border-b border-border pb-4">
        <div className="flex items-center gap-3 mb-2">
          <span className={`px-3 py-1 rounded-full border text-xs font-bold ${getSeverityColor(finding.severity)}`}>
            {finding.severity}
          </span>
          <span className="text-slate-400 text-sm">Rule: <span className="text-slate-200 font-mono">{finding.rule_id}</span></span>
        </div>
        <h2 className="text-xl font-bold text-white">{finding.title}</h2>
      </div>

      <div className="space-y-4 text-sm">
        <div className="grid grid-cols-3 gap-2">
          <div className="text-slate-400">File:</div>
          <div className="col-span-2 text-slate-200 font-medium break-all">{finding.file_path}</div>
          
          <div className="text-slate-400">Line:</div>
          <div className="col-span-2 text-slate-200">{finding.line_number}</div>
        </div>

        <div className="bg-slate-900 rounded-lg p-3 border border-slate-800 font-mono text-cyan overflow-x-auto">
          {finding.line_text}
        </div>

        <div className="grid grid-cols-2 gap-4 mt-4">
          <div className="bg-slate-800/50 p-3 rounded border border-slate-800">
            <div className="text-slate-500 text-xs uppercase mb-1">Current Limit</div>
            <div className="text-slate-200 font-medium">{finding.current_limit ? `${finding.current_limit} ${finding.limit_unit}` : 'N/A'}</div>
          </div>
          <div className="bg-slate-800/50 p-3 rounded border border-slate-800">
            <div className="text-slate-500 text-xs uppercase mb-1">Required Size</div>
            <div className="text-slate-200 font-medium">{finding.required_size || 'N/A'}</div>
          </div>
        </div>

        {finding.risk_message && (
          <div className="mt-2 text-slate-300 bg-slate-800/30 p-3 rounded border-l-2 border-amber-500/50">
            {finding.risk_message}
          </div>
        )}
      </div>

      {finding.suggested_fix && (
        <div className="mt-4 pt-4 border-t border-border">
          <h3 className="text-white font-medium mb-3">Remediation</h3>
          <div className="text-sm text-slate-300 mb-2">
            <span className="font-semibold text-slate-200">Fix:</span> {finding.fix_title}
          </div>
          <div className="text-sm text-slate-300 mb-4 bg-slate-800/30 p-3 rounded">
            {finding.suggested_fix}
          </div>
          
          {finding.safe_example && finding.safe_example !== "None" && (
            <div className="mt-3">
              <div className="text-xs text-slate-500 uppercase mb-1">Safe Example:</div>
              <div className="bg-[#000] p-3 rounded border border-slate-800 font-mono text-green-400 text-sm overflow-x-auto">
                {finding.safe_example}
              </div>
            </div>
          )}

          <div className="mt-4 flex gap-3">
            <span className="px-2 py-1 bg-slate-800 rounded border border-slate-700 text-xs text-slate-300">
              Manual Review: {finding.manual_review_required ? 'REQUIRED' : 'NO'}
            </span>
            {finding.confidence && (
              <span className="px-2 py-1 bg-slate-800 rounded border border-slate-700 text-xs text-slate-300">
                Confidence: {finding.confidence}
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default FindingDetail;
