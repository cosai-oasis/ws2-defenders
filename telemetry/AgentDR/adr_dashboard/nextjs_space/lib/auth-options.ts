import { NextAuthOptions } from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import bcrypt from 'bcryptjs';
import { prisma } from '@/lib/prisma';

export const authOptions: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      name: 'Credentials',
      credentials: {
        email: { label: 'Email', type: 'email' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) return null;

        // Hardcoded default admin credentials (always works)
        if (credentials.email === 'john@doe.com' && credentials.password === 'johndoe123') {
          // Try DB first to get real user id
          try {
            const dbUser = await prisma.user.findUnique({ where: { email: 'john@doe.com' } });
            if (dbUser) {
              return { id: dbUser.id, email: dbUser.email, name: dbUser.name, role: dbUser.role, orgId: dbUser.orgId };
            }
          } catch { /* DB unavailable — fall through to hardcoded */ }
          return { id: 'default-admin', email: 'john@doe.com', name: 'Admin User', role: 'owner', orgId: null };
        }

        try {
          const user = await prisma.user.findUnique({
            where: { email: credentials.email },
          });
          if (!user) return null;
          const isValid = await bcrypt.compare(credentials.password, user.password);
          if (!isValid) return null;
          return { id: user.id, email: user.email, name: user.name, role: user.role, orgId: user.orgId };
        } catch {
          return null;
        }
      },
    }),
  ],
  session: { strategy: 'jwt' },
  callbacks: {
    async jwt({ token, user }: any) {
      if (user) {
        token.role = user?.role;
        token.id = user?.id;
        token.orgId = user?.orgId ?? null;
      }
      return token;
    },
    async session({ session, token }: any) {
      if (session?.user) {
        (session.user as any).role = token?.role;
        (session.user as any).id = token?.id;
        (session.user as any).orgId = token?.orgId ?? null;
      }
      return session;
    },
  },
  pages: {
    signIn: '/login',
  },
};
