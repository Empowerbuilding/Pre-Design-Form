import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: 'standalone',
  // Allow large image uploads (up to 5 images x 5MB each). Next's default 10MB
  // body cap silently truncated multi-image submissions and broke FormData parsing.
  middlewareClientMaxBodySize: '25mb',
  images: {
    unoptimized: false,
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'hbfjdfxephlczkfgpceg.supabase.co',
        pathname: '/storage/v1/object/public/**',
      },
    ],
  },
};

export default nextConfig;
