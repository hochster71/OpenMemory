/**
 * middleware.ts — ORBIT auto-generated authentication middleware
 *
 * Enforces Supabase session on all /api/** and /dashboard/** routes.
 * Public routes (auth callbacks, login, sign-up, health check) are excluded.
 */

import { type NextRequest, NextResponse } from "next/server";
import { createServerClient }            from "@supabase/ssr";

// Routes that are explicitly public (no session required)
const PUBLIC_PREFIXES = [
  "/api/auth/",          // login / register / callback
  "/api/webhooks/",      // external webhooks (Stripe, GitHub, etc.) — verified via HMAC
  "/api/health",         // liveness probe
  "/login",
  "/register",
  "/sign-up",
  "/_next/",
  "/favicon",
];

function isPublic(pathname: string): boolean {
  return PUBLIC_PREFIXES.some((p) => pathname.startsWith(p));
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  if (isPublic(pathname)) {
    return NextResponse.next();
  }

  const response = NextResponse.next({
    request: { headers: request.headers },
  });

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll:  () => request.cookies.getAll(),
        setAll: (cookiesToSet) => {
          cookiesToSet.forEach(({ name, value, options }) => {
            request.cookies.set(name, value);
            response.cookies.set(name, value, options);
          });
        },
      },
    }
  );

  const { data: { user } } = await supabase.auth.getUser();

  // Redirect unauthenticated requests for page routes; 401 for API routes
  if (!user) {
    if (pathname.startsWith("/api/")) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("redirectTo", pathname);
    return NextResponse.redirect(loginUrl);
  }

  return response;
}

export const config = {
  matcher: [
    /*
     * Match all paths EXCEPT:
     *   - _next/static   (static assets)
     *   - _next/image    (image optimisation)
     *   - favicon.ico
     *   - public/*       (public folder files)
     */
    "/((?!_next/static|_next/image|favicon.ico|public/).*)",
  ],
};
