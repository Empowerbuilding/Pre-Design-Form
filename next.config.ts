import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: 'standalone',
  images: {
    unoptimized: false,  // Let Next.js handle optimization
  },
};

export default nextConfig;
