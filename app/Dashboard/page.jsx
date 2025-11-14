'use client';

import NavBar from "../../components/NavBar";
import ProtectedRoute from "../../components/ProtectedRoute";
import { useAuth } from "../../contexts/AuthContext";
import Link from "next/link";

export default function Dashboard() {
    const { user } = useAuth();

    return (
        <ProtectedRoute>
            <main className="min-h-screen bg-gray-50">
                <NavBar />

                <div className="max-w-6xl mx-auto px-4 md:px-8 py-8">
                    <h1 className="text-3xl font-bold text-gray-900 mb-8">
                        Dashboard
                    </h1>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
                            <h2 className="text-xl font-semibold text-gray-900 mb-4">Profile</h2>
                            <div className="space-y-3">
                                <div>
                                    <span className="text-sm text-gray-500">Email</span>
                                    <p className="text-gray-900">{user?.user_email}</p>
                                </div>
                                <div>
                                    <span className="text-sm text-gray-500">Role</span>
                                    <p className="text-gray-900 capitalize">{user?.user_role}</p>
                                </div>
                            </div>
                        </div>

                        <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
                            <h2 className="text-xl font-semibold text-gray-900 mb-4">Quick Actions</h2>
                            <div className="space-y-3">
                                <Link href="/CreateListing" className="block w-full bg-blue-600 text-white px-4 py-3 rounded-lg font-medium hover:bg-blue-700 transition-colors text-center">
                                    + Create New Listing
                                </Link>
                                <Link href="/Search_Browse" className="block w-full bg-gray-50 text-gray-700 px-4 py-3 rounded-lg font-medium hover:bg-gray-100 transition-colors text-center">
                                    Browse All Properties
                                </Link>
                            </div>
                        </div>
                    </div>

                    <div className="bg-white rounded-xl shadow-sm p-6 border border-gray-100">
                        <h2 className="text-xl font-semibold text-gray-900 mb-4">Saved Listings</h2>
                        <div className="text-center py-8">
                            <svg className="w-16 h-16 text-gray-300 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4.318 6.318a4.5 4.5 0 000 6.364L12 20.364l7.682-7.682a4.5 4.5 0 00-6.364-6.364L12 7.636l-1.318-1.318a4.5 4.5 0 00-6.364 0z" />
                            </svg>
                            <p className="text-gray-500 mb-4">No saved listings yet</p>
                            <Link href="/Search_Browse" className="text-blue-600 hover:text-blue-700 font-medium">
                                Start browsing properties →
                            </Link>
                        </div>
                    </div>
                </div>
            </main>
        </ProtectedRoute>
    );
}

