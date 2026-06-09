import React, { useState } from 'react';

function FindingsTable({ findings, onSelectFinding }) {
  const [filterSev, setFilterSev] = useState('ALL');
  const [search, setSearch] = useState('');

  const filteredFindings = findings.filter(f => {
    const matchesSev = filterSev === 'ALL' || f.severity === filterSev;
    const matchesSearch = search === '' || 
      f.file_path.toLowerCase().includes(search.toLowerCase()) || 
      f.rule_id.toLowerCase().includes(search.toLowerCase()) ||
      f.finding_type.toLowerCase().includes(search.toLowerCase());
    return matchesSev && matchesSearch;
  });

  const getSeverityColor = (sev) => {
    switch(sev) {
      case 'CRITICAL': return 'text-critical';
      case 'HIGH': return 'text-high';
      case 'MEDIUM': return 'text-medium';
      case 'LOW': return 'text-low';
      default: return 'text-slate-300';
    }
  };

  return (
    <div className="flex flex-col h-full">
      {/* Table Controls */}
      <div className="p-4 border-b border-border bg-slate-900/50 flex flex-col sm:flex-row gap-4 items-center justify-between">
        <div className="flex gap-2">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
            <button
              key={sev}
              onClick={() => setFilterSev(sev)}
              className={`px-3 py-1 text-xs font-semibold rounded-full border transition-colors ${filterSev === sev ? 'bg-cyan text-dark border-cyan' : 'bg-transparent text-slate-400 border-slate-600 hover:border-slate-400'}`}
            >
              {sev}
            </button>
          ))}
        </div>
        <div className="relative w-full sm:w-64">
          <input
            type="text"
            placeholder="Search files or rules..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-slate-800 border border-border rounded-lg pl-3 pr-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-cyan"
          />
        </div>
      </div>

      {/* Table Content */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-left border-collapse">
          <thead className="sticky top-0 bg-slate-900 shadow-sm text-xs uppercase text-slate-400">
            <tr>
              <th className="px-4 py-3 font-medium">Severity</th>
              <th className="px-4 py-3 font-medium">Type</th>
              <th className="px-4 py-3 font-medium">Rule</th>
              <th className="px-4 py-3 font-medium">File</th>
              <th className="px-4 py-3 font-medium">Line</th>
              <th className="px-4 py-3 font-medium">Ratio</th>
              <th className="px-4 py-3 font-medium text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border text-sm">
            {filteredFindings.map((f, i) => (
              <tr key={i} className="hover:bg-slate-800/50 transition-colors group cursor-pointer" onClick={() => onSelectFinding(f)}>
                <td className={`px-4 py-3 font-bold ${getSeverityColor(f.severity)}`}>{f.severity}</td>
                <td className="px-4 py-3 text-slate-300">{f.finding_type}</td>
                <td className="px-4 py-3">
                  <span className="bg-slate-800 px-2 py-1 rounded text-xs border border-slate-700 text-slate-300">{f.rule_id}</span>
                </td>
                <td className="px-4 py-3 text-slate-200 truncate max-w-[150px]" title={f.file_path}>{f.file_path}</td>
                <td className="px-4 py-3 text-slate-400">{f.line_number}</td>
                <td className="px-4 py-3 text-slate-300">{f.overflow_ratio ? `${f.overflow_ratio}x` : '-'}</td>
                <td className="px-4 py-3 text-right">
                  <button 
                    onClick={(e) => { e.stopPropagation(); onSelectFinding(f); }}
                    className="text-cyan hover:text-cyan/80 font-medium text-xs uppercase"
                  >
                    Details
                  </button>
                </td>
              </tr>
            ))}
            {filteredFindings.length === 0 && (
              <tr>
                <td colSpan="7" className="px-4 py-8 text-center text-slate-500">
                  No findings match the current filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default FindingsTable;
