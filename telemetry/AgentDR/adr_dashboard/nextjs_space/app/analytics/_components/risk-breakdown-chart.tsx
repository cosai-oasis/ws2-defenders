'use client';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';

const riskColors: Record<string, string> = {
  low: '#22c55e',
  medium: '#eab308',
  high: '#f97316',
  critical: '#ef4444',
};

export default function RiskBreakdownChart({ data }: { data: any[] }) {
  const safeData = (data ?? []).map((d: any) => ({ name: d?.level ?? 'unknown', value: d?.count ?? 0 }));

  if (safeData.length === 0) {
    return <div className="flex items-center justify-center h-full text-sm text-muted-foreground">No risk data available</div>;
  }

  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={safeData} margin={{ top: 5, right: 10, left: 0, bottom: 25 }}>
        <XAxis
          dataKey="name"
          tickLine={false}
          tick={{ fontSize: 10 }}
          label={{ value: 'Risk Level', position: 'insideBottom', offset: -15, style: { textAnchor: 'middle', fontSize: 11 } }}
        />
        <YAxis tickLine={false} tick={{ fontSize: 10 }} />
        <Tooltip contentStyle={{ fontSize: 11, backgroundColor: 'hsl(222, 47%, 9%)', border: '1px solid hsl(222, 47%, 16%)', borderRadius: '8px', color: '#fff' }} />
        <Bar dataKey="value" radius={[6, 6, 0, 0]}>
          {safeData.map((entry: any, i: number) => (
            <Cell key={i} fill={riskColors[entry?.name] ?? '#60B5FF'} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
