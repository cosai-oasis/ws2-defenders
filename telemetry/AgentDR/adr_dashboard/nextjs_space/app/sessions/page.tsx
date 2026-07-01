import { DashboardLayout } from '@/components/dashboard-layout';
import { SessionsContent } from './_components/sessions-content';

export default function SessionsPage() {
  return (
    <DashboardLayout>
      <SessionsContent />
    </DashboardLayout>
  );
}
