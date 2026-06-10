import { useState, useEffect } from 'react';
import SummaryCards from './components/SummaryCards';
import ReadinessScore from './components/ReadinessScore';
import SeverityBreakdown from './components/SeverityBreakdown';
import FindingsTable from './components/FindingsTable';
import FindingDetail from './components/FindingDetail';
import SuggestedFixes from './components/SuggestedFixes';
import BlastRadiusGraph from './components/BlastRadiusGraph';

function App() {
  const [activeTab, setActiveTab] = useState('table');
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [reportData, setReportData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetch('/agilityshift-report.json')
      .then((res) => {
        if (!res.ok) {
          throw new Error('Report not found. Please run the agilityshift scanner first.');
        }
        return res.json();
      })
      .then((data) => {
        setReportData(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-dark text-slate-100 flex items-center justify-center font-sans">
        <div className="text-xl font-semibold animate-pulse text-cyan">Loading AgilityShift Report...</div>
      </div>
    );
  }

  if (error || !reportData) {
    return (
      <div className="min-h-screen bg-dark text-slate-100 flex items-center justify-center font-sans">
        <div className="bg-card border border-border p-8 rounded-xl max-w-lg text-center">
          <h2 className="text-2xl font-bold text-critical mb-4">No Scan Data Found</h2>
          <p className="text-slate-400 mb-6">{error || 'Could not load report data.'}</p>
          <div className="bg-dark p-4 rounded-lg text-left font-mono text-sm border border-border text-slate-300">
            $ agilityshift scan ./examples/vulnerable-python-api --report all
          </div>
        </div>
      </div>
    );
  }

  const { scan, severity_summary, findings } = reportData;

  const handleSelectFinding = (finding) => {
    setSelectedFinding(finding);
  };

  const criticalCount = severity_summary.CRITICAL || 0;

  return (
    <div className="min-h-screen bg-dark text-slate-100 p-6 font-sans">
      <div className="max-w-7xl mx-auto space-y-8">
        
        {/* Header */}
        <header className="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-border pb-6">
          <div>
            <h1 className="text-3xl font-bold text-white tracking-tight">AgilityShift</h1>
            <p className="text-slate-400 mt-1">PQC Migration Breakage Dashboard</p>
          </div>
          <div className="mt-4 md:mt-0 bg-card border border-border px-4 py-2 rounded-lg">
            <span className="text-slate-400 text-sm">Target Profile: </span>
            <span className="text-cyan font-semibold">{scan.target_profile}</span>
          </div>
        </header>

        {/* Hero Warning Banner */}
        {criticalCount > 0 ? (
          <div className="bg-critical/10 border-l-4 border-critical p-6 rounded-r-lg flex items-start space-x-4">
            <div className="flex-1">
              <h2 className="text-xl font-bold text-critical mb-1">Production Breakage Risk Detected</h2>
              <p className="text-red-200">Critical PQC migration risks were found across code, database, and API layers.</p>
            </div>
          </div>
        ) : (
          <div className="bg-low/10 border-l-4 border-low p-6 rounded-r-lg">
            <h2 className="text-xl font-bold text-low mb-1">Migration Ready</h2>
            <p className="text-emerald-200">No critical PQC migration blockers detected.</p>
          </div>
        )}

        {/* Summary Row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2">
            <SummaryCards 
              scan={scan} 
              severitySummary={severity_summary} 
              totalFindings={findings.length} 
            />
            <div className="mt-6">
              <SeverityBreakdown severitySummary={severity_summary} />
            </div>
          </div>
          <div className="bg-card border border-border rounded-xl p-6 flex flex-col items-center justify-center">
            <ReadinessScore score={scan.readiness_score} />
          </div>
        </div>

        {/* CI/CD Gate Visual */}
        <div className="bg-card border border-border rounded-xl p-6 flex flex-col md:flex-row items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-white mb-2">CI/CD Gate</h3>
            <p className="text-slate-400 mb-1">Fail-on threshold: <span className="text-white font-medium">CRITICAL</span></p>
            <p className="text-slate-400">Deployment blocked before production failure.</p>
          </div>
          <div className="mt-4 md:mt-0 bg-critical/20 text-critical font-bold px-6 py-3 rounded-lg border border-critical">
            Status: FAILED
          </div>
        </div>

        {/* View Toggle */}
        <div className="flex space-x-2 border-b border-border pb-2">
          <button 
            className={`px-4 py-2 rounded-t-lg font-medium transition-colors ${activeTab === 'table' ? 'bg-card text-white border-t border-l border-r border-border' : 'text-slate-400 hover:text-white'}`}
            onClick={() => setActiveTab('table')}
          >
            Findings Table
          </button>
          <button 
            className={`px-4 py-2 rounded-t-lg font-medium transition-colors ${activeTab === 'graph' ? 'bg-card text-white border-t border-l border-r border-border' : 'text-slate-400 hover:text-white'}`}
            onClick={() => setActiveTab('graph')}
          >
            Blast Radius Graph
          </button>
        </div>

        {/* Main Content Area */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 flex flex-col h-[600px] bg-card border border-border rounded-xl overflow-hidden">
            {activeTab === 'table' ? (
              <FindingsTable findings={findings} onSelectFinding={handleSelectFinding} />
            ) : (
              <BlastRadiusGraph reportData={reportData} />
            )}
          </div>
          <div className="bg-card border border-border rounded-xl overflow-hidden h-[600px] overflow-y-auto">
            <FindingDetail finding={selectedFinding} />
          </div>
        </div>

        {/* Suggested Fixes */}
        <div>
          <h2 className="text-2xl font-bold text-white mb-6">Suggested Fixes</h2>
          <SuggestedFixes findings={findings} />
        </div>
      </div>
    </div>
  );
}

export default App;
