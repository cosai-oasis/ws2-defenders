'use client';
import { usePathname } from 'next/navigation';
import Link from 'next/link';
import Image from 'next/image';
import { signOut, useSession } from 'next-auth/react';
import { useState } from 'react';
import {
  Shield, LayoutDashboard, Activity, ScrollText, BarChart3,
  AlertTriangle, Menu, X, LogOut, ChevronLeft, User,
  ShieldCheck, Settings, GitBranch, Brain, ShieldHalf,
} from 'lucide-react';
import { cn } from '@/lib/utils';

const navItems = [
  { href: '/dashboard', label: 'Overview', icon: LayoutDashboard },
  { href: '/activity', label: 'Live Feed', icon: Activity },
  { href: '/sessions', label: 'Sessions', icon: GitBranch },
  { href: '/ueba', label: 'UEBA Baselines', icon: Brain },
  { href: '/logs', label: 'Event Logs', icon: ScrollText },
  { href: '/analytics', label: 'Analytics', icon: BarChart3 },
  { href: '/alerts', label: 'Alerts', icon: AlertTriangle },
  { href: '/policies', label: 'Policies', icon: ShieldCheck },
  { href: '/llm-guard', label: 'LLM Guard', icon: ShieldHalf },
  { href: '/settings', label: 'Settings', icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const { data: session } = useSession() || {};
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <>
      {/* Mobile toggle */}
      <button
        onClick={() => setMobileOpen(true)}
        className="fixed top-4 left-4 z-50 md:hidden p-2 rounded-lg bg-card border border-border"
        aria-label="Open menu"
      >
        <Menu className="w-5 h-5" />
      </button>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div className="fixed inset-0 bg-black/50 z-40 md:hidden" onClick={() => setMobileOpen(false)} />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          'fixed top-0 left-0 h-full z-50 flex flex-col transition-all duration-300 bg-card border-r border-border',
          collapsed ? 'w-[68px]' : 'w-64',
          mobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'
        )}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-border">
          <div className={cn('flex items-center gap-3', collapsed && 'justify-center w-full')}>
            {collapsed ? (
              <div className="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
                <Shield className="w-5 h-5 text-primary" />
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <Image src="/cosai-logo.png" alt="CoSAI" width={100} height={41} className="h-7 w-auto dark:brightness-0 dark:invert" priority />
                <span className="font-display font-bold text-sm leading-tight">ADR</span>
              </div>
            )}
          </div>
          <button
            onClick={() => setMobileOpen(false)}
            className="md:hidden text-muted-foreground"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 py-4 px-2 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const isActive = pathname === item.href || pathname?.startsWith(item.href + '/');
            return (
              <Link
                key={item.href}
                href={item.href}
                onClick={() => setMobileOpen(false)}
                className={cn(
                  'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all',
                  collapsed && 'justify-center px-2',
                  isActive
                    ? 'bg-primary/10 text-primary'
                    : 'text-muted-foreground hover:text-foreground hover:bg-accent/50'
                )}
              >
                <item.icon className="w-5 h-5 flex-shrink-0" />
                {!collapsed && <span>{item.label}</span>}
              </Link>
            );
          })}
        </nav>

        {/* Footer */}
        <div className="border-t border-border p-3">
          {!collapsed && session?.user && (
            <div className="flex items-center gap-2 px-2 py-2 mb-2">
              <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center">
                <User className="w-4 h-4 text-primary" />
              </div>
              <div className="min-w-0">
                <p className="text-xs font-medium truncate">{session?.user?.name ?? 'User'}</p>
                <p className="text-[10px] text-muted-foreground truncate">{session?.user?.email ?? ''}</p>
              </div>
            </div>
          )}
          <div className="flex items-center gap-1">
            <button
              onClick={() => setCollapsed(!collapsed)}
              className="hidden md:flex items-center justify-center w-full p-2 rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent/50 transition-colors"
              aria-label="Toggle sidebar"
            >
              <ChevronLeft className={cn('w-4 h-4 transition-transform', collapsed && 'rotate-180')} />
            </button>
            <button
              onClick={() => signOut({ callbackUrl: '/login' })}
              className={cn(
                'flex items-center gap-2 p-2 rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent/50 transition-colors text-sm',
                collapsed ? 'w-full justify-center' : 'w-full'
              )}
            >
              <LogOut className="w-4 h-4" />
              {!collapsed && <span>Sign Out</span>}
            </button>
          </div>
        </div>
      </aside>
    </>
  );
}