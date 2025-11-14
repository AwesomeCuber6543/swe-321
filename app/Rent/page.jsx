'use client';

import NavBar from "../../components/NavBar";
import Link from "next/link";

export default function Rent() {
  return (
    <main className="min-h-screen bg-gray-50">
      <NavBar />
      <div className="max-w-7xl mx-auto px-4 md:px-8 py-12">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">Rent a Home</h1>
          <p className="text-gray-600">Browse rental properties</p>
        </div>

        <div className="bg-white rounded-xl shadow-sm p-12 border border-gray-100 text-center">
          <svg className="w-20 h-20 text-gray-300 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
          </svg>
          <h2 className="text-xl font-semibold text-gray-900 mb-2">Coming Soon</h2>
          <p className="text-gray-500 mb-6">Rental listings will be available soon</p>
          <Link href="/Search_Browse" className="inline-block bg-blue-600 text-white px-6 py-3 rounded-lg font-medium hover:bg-blue-700 transition-colors">
            Try Search Instead
          </Link>
        </div>
      </div>
    </main>
  );
}