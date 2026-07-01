import { withAuth } from 'next-auth/middleware';

export default withAuth({
  pages: { signIn: '/login' },
});

export const config = {
  matcher: [
    '/dashboard/:path*',
    '/activity/:path*',
    '/logs/:path*',
    '/analytics/:path*',
    '/alerts/:path*',
    '/policies/:path*',
    '/settings/:path*',
  ],
};
