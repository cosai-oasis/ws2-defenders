import { cn } from '@/lib/utils'

export function Section({
  children, className, id,
}: {
  children: React.ReactNode; className?: string; id?: string
}) {
  return (
    <section id={id} className={cn('py-16 sm:py-24 scroll-mt-28', className)}>
      {children}
    </section>
  )
}
