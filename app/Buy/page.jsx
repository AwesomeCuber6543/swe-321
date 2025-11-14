'use client';

import NavBar from "../../components/NavBar";
import Link from "next/link";

export default function Buy() {
  return (
    <main className="min-h-screen bg-gray-50">
      <NavBar />
      <div className="max-w-7xl mx-auto px-4 md:px-8 py-12">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">Buy a Home</h1>
          <p className="text-gray-600">Browse homes available for purchase</p>
        </div>

        <div className="bg-white rounded-xl shadow-sm p-12 border border-gray-100 text-center">
          <svg className="w-20 h-20 text-gray-300 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
          </svg>
          <h2 className="text-xl font-semibold text-gray-900 mb-2">Coming Soon</h2>
          <p className="text-gray-500 mb-6">Browse functionality will be available soon</p>
          <Link href="/Search_Browse" className="inline-block bg-blue-600 text-white px-6 py-3 rounded-lg font-medium hover:bg-blue-700 transition-colors">
            Try Search Instead
          </Link>
        </div>
      </div>
    </main>
  );
}