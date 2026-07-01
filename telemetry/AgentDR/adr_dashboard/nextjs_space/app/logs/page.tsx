import { DashboardLayout } from '@/components/dashboard-layout';
import { LogViewer } from './_components/log-viewer';

export default function LogsPage() {
  return (
    <DashboardLayout>
      <LogViewer />
    </DashboardLayout>
  );
}
