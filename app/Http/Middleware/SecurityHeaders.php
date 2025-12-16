<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class SecurityHeaders
{
    public function handle(Request $request, Closure $next)
    {
        $response = $next($request);

        // Remove PHP fingerprint
        $response->headers->remove('X-Powered-By');

        // Clickjacking protection
        $response->headers->set('X-Frame-Options', 'SAMEORIGIN');

        // MIME sniffing protection
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        // Referrer policy
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');

        // Minimal permissions policy
        $response->headers->set('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

        // CSP baseline
        $csp = "default-src 'self'; "
            . "base-uri 'self'; "
            . "form-action 'self'; "
            . "frame-ancestors 'self'; "
            . "object-src 'none'; "
            . "img-src 'self' data:; "
            . "font-src 'self' data:; "
            . "script-src 'self'; "
            . "style-src 'self';";

        $response->headers->set('Content-Security-Policy', $csp);

        return $response;
    }
}
