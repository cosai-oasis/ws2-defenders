'use client';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip, Legend } from 'recharts';

const COLORS = ['#60B5FF', '#FF9149', '#FF9898', '#FF90BB', '#FF6363', '#80D8C3', '#A19AD3', '#72BF78', '#5DADE2', '#F1948A', '#82E0AA', '#D7BDE2', '#F0B27A', '#85C1E9'];

export default function TypeDistributionChart({ data }: { data: any[] }) {
  const safeData = (data ?? []).map((d: any) => ({ name: d?.type ?? 'unknown', value: d?.count ?? 0 }));

  if (safeData.length === 0) {
    return <div className="flex items-center justify-center h-full text-sm text-muted-foreground">No event type data available</div>;
  }

  return (
    <ResponsiveContainer width="100%" height="100%">
      <PieChart>
        <Pie
          data={safeData}
          dataKey="value"
          nameKey="name"
          cx="50%"
          cy="55%"
          innerRadius={50}
          outerRadius={90}
          paddingAngle={2}
          label={({ name, percent }: any) => `${(name ?? '').slice(0, 12)} ${((percent ?? 0) * 100)?.toFixed?.(0)}%`}
          labelLine={{ strokeWidth: 1 }}
        >
          {safeData.map((_: any, i: number) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
        </Pie>
        <Tooltip contentStyle={{ fontSize: 11, backgroundColor: 'hsl(222, 47%, 9%)', border: '1px solid hsl(222, 47%, 16%)', borderRadius: '8px', color: '#fff' }} />
        <Legend verticalAlign="top" wrapperStyle={{ fontSize: 11 }} />
      </PieChart>
    </ResponsiveContainer>
  );
}
