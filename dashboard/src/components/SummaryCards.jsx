

function SummaryCards({ scan, severitySummary, totalFindings }) {
  const stats = [
    { label: 'Files Scanned', value: scan.files_scanned },
    { label: 'Total Findings', value: totalFindings },
    { label: 'Critical Issues', value: severitySummary.CRITICAL || 0, color: 'text-critical' },
    { label: 'High Issues', value: severitySummary.HIGH || 0, color: 'text-high' },
    { label: 'Required Size', value: `${scan.required_signature_size} bytes` },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
      {stats.map((stat, idx) => (
        <div key={idx} className="bg-card border border-border rounded-xl p-4 flex flex-col justify-center">
          <span className="text-slate-400 text-xs uppercase tracking-wider mb-1">{stat.label}</span>
          <span className={`text-2xl font-bold ${stat.color || 'text-white'}`}>{stat.value}</span>
        </div>
      ))}
    </div>
  );
}

export default SummaryCards;
