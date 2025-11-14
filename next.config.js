/** @type {import('next').NextConfig} */
const nextConfig = {
  // Image Configuration (Fixes the quality warning)
  images: {
    qualities: [100, 75], // Explicitly allows the quality={100} setting
    minimumCacheTTL: 60,
  },
  // You can add other config options here if needed
};

module.exports = nextConfig;