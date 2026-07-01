'use client'

import { useState } from 'react'
import { cn } from '@/lib/utils'
import { PanelLeft } from 'lucide-react'
import { Button } from '@/components/ui/button'

export function AppShell({
  sidebar,
  header,
  children,
  className,
}: {
  sidebar: React.ReactNode
  header?: React.ReactNode
  children: React.ReactNode
  className?: string
}) {
  const [sidebarOpen, setSidebarOpen] = useState(false)

  return (
    <div className="min-h-screen bg-background">
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-background/80 backdrop-blur-sm lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          'fixed inset-y-0 left-0 z-50 w-64 border-r bg-card transition-transform duration-normal ease-out lg:translate-x-0',
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        )}
      >
        <div className="flex h-full flex-col overflow-y-auto p-4">
          {sidebar}
        </div>
      </aside>

      {/* Main area */}
      <div className="lg:pl-64">
        {/* Header */}
        <header className="sticky top-0 z-30 flex h-14 items-center gap-4 border-b bg-card/80 backdrop-blur-md px-4 sm:px-6">
          <Button
            variant="ghost"
            size="icon"
            className="lg:hidden"
            onClick={() => setSidebarOpen(true)}
          >
            <PanelLeft className="h-5 w-5" />
          </Button>
          {header}
        </header>

        {/* Content */}
        <main className={cn('p-4 sm:p-6 lg:p-8', className)}>
          {children}
        </main>
      </div>
    </div>
  )
}
