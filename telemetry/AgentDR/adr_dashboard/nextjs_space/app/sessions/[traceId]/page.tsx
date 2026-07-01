import { DashboardLayout } from '@/components/dashboard-layout';
import { SessionDetail } from '../_components/session-detail';

interface PageProps { params: { traceId: string } }

export default function SessionDetailPage({ params }: PageProps) {
  return (
    <DashboardLayout>
      <SessionDetail traceId={params.traceId} />
    </DashboardLayout>
  );
}
