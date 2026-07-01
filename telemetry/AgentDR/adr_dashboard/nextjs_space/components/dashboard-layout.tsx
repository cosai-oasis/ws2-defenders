'use client';
import { Sidebar } from '@/components/sidebar';
import { useState } from 'react';

export function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-background">
      <Sidebar />
      <main className="md:ml-64 min-h-screen transition-all duration-300">
        {children}
      </main>
    </div>
  );
}
