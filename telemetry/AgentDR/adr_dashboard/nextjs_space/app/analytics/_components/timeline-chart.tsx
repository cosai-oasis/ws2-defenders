'use client';
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, Legend
} from 'recharts';

export default function TimelineChart({ data }: { data: any[] }) {
  const safeData = (data ?? []).map((d: any) => ({
    hour: d?.hour?.slice?.(5, 13) ?? '',
    low: d?.low ?? 0,
    medium: d?.medium ?? 0,
    high: d?.high ?? 0,
    critical: d?.critical ?? 0,
    total: d?.total ?? 0,
  }));

  if (safeData.length === 0) {
    return <div className="flex items-center justify-center h-full text-sm text-muted-foreground">No timeline data available</div>;
  }

  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={safeData} margin={{ top: 5, right: 10, left: 0, bottom: 25 }}>
        <XAxis
          dataKey="hour"
          tickLine={false}
          tick={{ fontSize: 10 }}
          interval="preserveStartEnd"
          angle={-45}
          textAnchor="end"
          height={50}
          label={{ value: 'Time', position: 'insideBottom', offset: -15, style: { textAnchor: 'middle', fontSize: 11 } }}
        />
        <YAxis tickLine={false} tick={{ fontSize: 10 }} />
        <Tooltip contentStyle={{ fontSize: 11, backgroundColor: 'hsl(222, 47%, 9%)', border: '1px solid hsl(222, 47%, 16%)', borderRadius: '8px', color: '#fff' }} />
        <Legend verticalAlign="top" wrapperStyle={{ fontSize: 11 }} />
        <Area type="monotone" dataKey="critical" stackId="1" fill="#ef4444" stroke="#ef4444" fillOpacity={0.6} />
        <Area type="monotone" dataKey="high" stackId="1" fill="#f97316" stroke="#f97316" fillOpacity={0.6} />
        <Area type="monotone" dataKey="medium" stackId="1" fill="#eab308" stroke="#eab308" fillOpacity={0.6} />
        <Area type="monotone" dataKey="low" stackId="1" fill="#22c55e" stroke="#22c55e" fillOpacity={0.6} />
      </AreaChart>
    </ResponsiveContainer>
  );
}
