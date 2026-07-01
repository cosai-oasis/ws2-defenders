'use client';

const HOURS = Array.from({ length: 24 }, (_, i) => i);

export default function HeatmapChart({ data }: { data: Record<string, Record<number, number>> }) {
  const safeData = data ?? {};
  const types = Object.keys(safeData).slice(0, 8);

  if (types.length === 0) {
    return <div className="flex items-center justify-center h-full text-sm text-muted-foreground">No heatmap data available</div>;
  }

  let maxVal = 1;
  for (const type of types) {
    for (const h of HOURS) {
      const v = safeData[type]?.[h] ?? 0;
      if (v > maxVal) maxVal = v;
    }
  }

  const getColor = (val: number) => {
    if (val === 0) return 'bg-muted/30';
    const intensity = val / maxVal;
    if (intensity < 0.25) return 'bg-blue-900/40';
    if (intensity < 0.5) return 'bg-blue-700/50';
    if (intensity < 0.75) return 'bg-blue-500/60';
    return 'bg-blue-400/80';
  };

  return (
    <div className="overflow-x-auto h-full">
      <div className="min-w-[600px]">
        <div className="flex gap-0.5 mb-1 ml-[120px]">
          {HOURS.map((h) => (
            <div key={h} className="flex-1 text-center text-[8px] text-muted-foreground">
              {h}h
            </div>
          ))}
        </div>
        {types.map((type) => (
          <div key={type} className="flex items-center gap-0.5 mb-0.5">
            <div className="w-[120px] text-[10px] font-mono text-muted-foreground truncate pr-2 text-right">
              {type}
            </div>
            {HOURS.map((h) => {
              const val = safeData[type]?.[h] ?? 0;
              return (
                <div
                  key={h}
                  className={`flex-1 aspect-square rounded-sm ${getColor(val)} transition-colors hover:ring-1 hover:ring-primary/50`}
                  title={`${type} @ ${h}:00 - ${val} events`}
                />
              );
            })}
          </div>
        ))}
        <div className="flex items-center gap-2 mt-3 ml-[120px]">
          <span className="text-[10px] text-muted-foreground">Less</span>
          <div className="flex gap-0.5">
            {['bg-muted/30', 'bg-blue-900/40', 'bg-blue-700/50', 'bg-blue-500/60', 'bg-blue-400/80'].map((c, i) => (
              <div key={i} className={`w-3 h-3 rounded-sm ${c}`} />
            ))}
          </div>
          <span className="text-[10px] text-muted-foreground">More</span>
        </div>
      </div>
    </div>
  );
}
