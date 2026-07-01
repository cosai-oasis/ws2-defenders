import { cn } from '@/lib/utils'

type Size = 'sm' | 'md' | 'lg' | 'xl' | 'full'

const sizes: Record<Size, string> = {
  sm:   'max-w-2xl',
  md:   'max-w-4xl',
  lg:   'max-w-6xl',
  xl:   'max-w-7xl',
  full: 'max-w-full',
}

export function Container({
  children, size = 'lg', className,
}: {
  children: React.ReactNode; size?: Size; className?: string
}) {
  return (
    <div className={cn('mx-auto w-full px-4 sm:px-6 lg:px-8', sizes[size], className)}>
      {children}
    </div>
  )
}
