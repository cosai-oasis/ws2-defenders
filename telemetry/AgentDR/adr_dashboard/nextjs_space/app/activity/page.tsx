import { DashboardLayout } from '@/components/dashboard-layout';
import { ActivityFeed } from './_components/activity-feed';

export default function ActivityPage() {
  return (
    <DashboardLayout>
      <ActivityFeed />
    </DashboardLayout>
  );
}
