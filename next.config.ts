import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: 'standalone',
  // Allow large image uploads (up to 5 images x 5MB each). Next's default 10MB
  // body cap silently truncated multi-image submissions and broke FormData parsing.
  // NOTE: in Next 15.5 this key is read from config.experimental — top-level is ignored.
  experimental: {
    middlewareClientMaxBodySize: '25mb',
  },
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
