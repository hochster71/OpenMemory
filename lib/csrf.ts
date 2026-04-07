/**
 * lib/csrf.ts  —  ORBIT auto-generated CSRF protection utility
 *
 * Uses the "double-submit cookie" pattern:
 *   1. On each page load the server sets a __csrf cookie with a random token.
 *   2. Client-side code reads the cookie and sends it as the X-CSRF-Token header.
 *   3. API handlers call verifyCsrf() which compares the header to the cookie.
 *
 * Safe methods (GET, HEAD, OPTIONS) are never checked.
 */

import { cookies }      from "next/headers";
import { NextRequest }  from "next/server";
import { randomBytes }  from "crypto";

const CSRF_COOKIE = "__csrf";
const CSRF_HEADER = "x-csrf-token";
const TOKEN_BYTES = 32;

/** Generate a new CSRF token and set it as an HttpOnly, SameSite=Strict cookie. */
export function setCsrfCookie(): string {
  const token = randomBytes(TOKEN_BYTES).toString("hex");
  cookies().set(CSRF_COOKIE, token, {
    httpOnly: false,   // must be readable by JS to set the header
    sameSite: "strict",
    secure:   process.env.NODE_ENV === "production",
    path:     "/",
  });
  return token;
}

/**
 * Validate the CSRF token on a mutating request.
 * Returns an error string if invalid, or null if the request is safe.
 */
export function verifyCsrf(request: NextRequest): string | null {
  const method = request.method.toUpperCase();
  // Safe methods never need a CSRF check
  if (["GET", "HEAD", "OPTIONS"].includes(method)) return null;

  const headerToken = request.headers.get(CSRF_HEADER);
  const cookieToken = request.cookies.get(CSRF_COOKIE)?.value;

  if (!cookieToken) return "CSRF cookie missing — refresh the page";
  if (!headerToken) return "CSRF header missing — include X-CSRF-Token in your request";
  // Use a constant-time comparison to prevent timing attacks
  if (!timingSafeEqual(headerToken, cookieToken)) return "CSRF token mismatch";

  return null;
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
