import React, { useMemo, useRef, useEffect, useState } from 'react';
import ForceGraph2D from 'react-force-graph-2d';

export default function BlastRadiusGraph({ reportData }) {
  const fgRef = useRef();
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });
  const containerRef = useRef();

  useEffect(() => {
    const updateDimensions = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.clientWidth,
          height: containerRef.current.clientHeight
        });
      }
    };
    
    updateDimensions();
    window.addEventListener('resize', updateDimensions);
    return () => window.removeEventListener('resize', updateDimensions);
  }, []);

  const graphData = useMemo(() => {
    if (!reportData || !reportData.findings) return { nodes: [], links: [] };

    const nodes = [];
    const links = [];
    
    const rootId = 'root';
    nodes.push({
      id: rootId,
      name: reportData.scan?.target_profile || 'PQC Profile',
      val: 20,
      color: '#06b6d4', // cyan
      group: 0
    });

    const fileNodes = new Set();

    reportData.findings.forEach((finding, index) => {
      const fileId = `file-${finding.file_path}`;
      if (!fileNodes.has(fileId)) {
        fileNodes.add(fileId);
        nodes.push({
          id: fileId,
          name: finding.file_path,
          val: 10,
          color: '#94a3b8', // slate-400
          group: 1
        });
        links.push({
          source: rootId,
          target: fileId
        });
      }

      const findingId = `finding-${index}`;
      nodes.push({
        id: findingId,
        name: `L${finding.line_number}: ${finding.rule_id}`,
        val: 5,
        color: finding.severity === 'CRITICAL' ? '#ef4444' : finding.severity === 'HIGH' ? '#f97316' : '#eab308',
        group: 2,
        finding: finding
      });
      
      links.push({
        source: fileId,
        target: findingId
      });
    });

    return { nodes, links };
  }, [reportData]);

  // Handle zoom to fit on initial render
  useEffect(() => {
    if (fgRef.current) {
      setTimeout(() => {
        fgRef.current.zoomToFit(400, 50);
      }, 500);
    }
  }, [graphData]);

  return (
    <div ref={containerRef} className="w-full h-full bg-dark/50 rounded-xl overflow-hidden relative">
      <div className="absolute top-4 left-4 z-10 bg-card/80 border border-border p-3 rounded-lg backdrop-blur-sm">
        <h3 className="text-white font-semibold text-sm mb-2">Blast Radius Legend</h3>
        <div className="space-y-1 text-xs">
          <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-cyan"></div><span className="text-slate-300">Target Profile</span></div>
          <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-slate-400"></div><span className="text-slate-300">Impacted File</span></div>
          <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-red-500"></div><span className="text-slate-300">Critical Asset Risk</span></div>
          <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-orange-500"></div><span className="text-slate-300">High Asset Risk</span></div>
        </div>
      </div>
      
      <ForceGraph2D
        ref={fgRef}
        width={dimensions.width}
        height={dimensions.height}
        graphData={graphData}
        nodeLabel="name"
        nodeColor="color"
        nodeRelSize={1}
        linkDirectionalParticles={2}
        linkDirectionalParticleSpeed={0.005}
        linkColor={() => '#334155'} // slate-700
        backgroundColor="transparent"
        onNodeClick={(node) => {
          if (node.group === 2 && node.finding) {
            // Optional: integration with the rest of the dashboard
            console.log('Clicked finding:', node.finding);
          }
          
          // Center on node
          fgRef.current.centerAt(node.x, node.y, 1000);
          fgRef.current.zoom(8, 2000);
        }}
      />
    </div>
  );
}
