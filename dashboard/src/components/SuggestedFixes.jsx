

function SuggestedFixes({ findings }) {
  const fixableFindings = findings.filter(f => f.suggested_fix);
  
  const sortOrder = { 'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4 };
  fixableFindings.sort((a, b) => sortOrder[a.severity] - sortOrder[b.severity]);

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
  };

  if (fixableFindings.length === 0) return <p className="text-slate-500">No suggested fixes available.</p>;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      {fixableFindings.map((f, i) => (
        <div key={i} className="bg-card border border-border rounded-xl p-5 hover:border-slate-600 transition-colors">
          <div className="flex justify-between items-start mb-3 border-b border-border pb-3">
            <div>
              <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold border mb-2 ${
                f.severity === 'CRITICAL' ? 'bg-critical/20 text-critical border-critical' :
                f.severity === 'HIGH' ? 'bg-high/20 text-high border-high' :
                f.severity === 'MEDIUM' ? 'bg-medium/20 text-medium border-medium' :
                'bg-low/20 text-low border-low'
              }`}>
                {f.severity}
              </span>
              <div className="text-slate-300 text-sm font-medium">
                {f.file_path}:{f.line_number}
              </div>
            </div>
            <div className="text-right">
              <div className="text-xs text-slate-500 uppercase">Rule</div>
              <div className="text-xs font-mono text-slate-400 bg-slate-900 px-1 py-0.5 rounded border border-slate-800">{f.rule_id}</div>
            </div>
          </div>
          
          <div className="mb-2">
            <div className="text-white font-medium mb-1">{f.fix_title}</div>
            <div className="text-sm text-slate-400">{f.suggested_fix}</div>
          </div>

          {f.safe_example && f.safe_example !== "None" && (
            <div className="mt-4 relative group">
              <div className="text-xs text-slate-500 uppercase mb-1">Safe Example</div>
              <div className="bg-black p-3 rounded border border-slate-800 font-mono text-sm text-green-400 overflow-x-auto pr-10">
                {f.safe_example}
              </div>
              <button 
                onClick={() => handleCopy(f.safe_example)}
                className="absolute right-2 bottom-2 p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded opacity-0 group-hover:opacity-100 transition-opacity border border-slate-600"
                title="Copy to clipboard"
              >
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 20 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
              </button>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

export default SuggestedFixes;
