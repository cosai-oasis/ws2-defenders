'use client';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';

export default function AgentChart({ data }: { data: any[] }) {
  const safeData = (data ?? []).map((d: any) => ({ name: d?.agent ?? 'Unknown', value: d?.count ?? 0 }));

  if (safeData.length === 0) {
    return <div className="flex items-center justify-center h-full text-sm text-muted-foreground">No agent data available</div>;
  }

  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={safeData} layout="vertical" margin={{ top: 5, right: 20, left: 10, bottom: 5 }}>
        <XAxis type="number" tickLine={false} tick={{ fontSize: 10 }} />
        <YAxis dataKey="name" type="category" tickLine={false} tick={{ fontSize: 10 }} width={100} />
        <Tooltip contentStyle={{ fontSize: 11, backgroundColor: 'hsl(222, 47%, 9%)', border: '1px solid hsl(222, 47%, 16%)', borderRadius: '8px', color: '#fff' }} />
        <Bar dataKey="value" fill="#A19AD3" radius={[0, 6, 6, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}
