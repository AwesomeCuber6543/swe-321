'use client';

import { useState, useEffect } from "react";
import { useSearchParams } from "next/navigation";
import NavBar from "../../components/NavBar";
import ListingCard from "../../components/ListingCard";
import SearchBar from "../../components/SearchBar";
import { ListingsService } from "../../lib/listings";

export default function Search_Browse() {
    const [listings, setListings] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const searchParams = useSearchParams();
    const query = searchParams.get('q');

    useEffect(() => {
        const fetchListings = async () => {
            setLoading(true);
            setError('');
            try {
                let data;
                if (query) {
                    try {
                        const results = await ListingsService.naturalLanguageSearch(query, null, 20);
                        data = results.map(r => r.listing);
                        if (data.length === 0) {
                            setError('🤖 AI search is not available yet. Create some listings with images to enable natural language search! Showing all listings below.');
                            data = await ListingsService.getAllListings({ limit: 50 });
                        }
                    } catch (searchErr) {
                        console.error("Search failed, falling back to all listings:", searchErr);
                        setError('🤖 AI search is not available yet. Create some listings with images to enable it! Showing all listings below.');
                        data = await ListingsService.getAllListings({ limit: 50 });
                    }
                } else {
                    data = await ListingsService.getAllListings({ limit: 50 });
                }
                setListings(data);
            } catch (err) {
                console.error("Failed to fetch listings:", err);
                setError('Failed to load listings. Please try again.');
            } finally {
                setLoading(false);
            }
        };
        fetchListings();
    }, [query]);

    return (
        <main className="min-h-screen bg-gray-50">
            <div className="sticky top-0 z-10 bg-white border-b border-gray-200">
                <NavBar />
                <div className="max-w-7xl mx-auto px-4 md:px-8 py-4">
                    <div className="flex flex-col md:flex-row gap-4 items-center">
                        <div className="flex-grow w-full">
                            <SearchBar initialQuery={query} />
                        </div>
                        <div className="flex gap-3">
                            <button className="px-4 py-2 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 hover:bg-gray-50 transition-colors">
                                Sort
                            </button>
                            <button className="px-4 py-2 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 hover:bg-gray-50 transition-colors">
                                Filter
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            <div className="max-w-7xl mx-auto px-4 md:px-8 py-8">
                {query && (
                    <div className="mb-6">
                        <p className="text-gray-600">
                            Search results for: <span className="font-semibold text-gray-900">{query}</span>
                        </p>
                    </div>
                )}
                
                {error && (
                    <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg mb-6">
                        {error}
                    </div>
                )}
                
                {loading ? (
                    <div className="text-center py-12">
                        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
                        <p className="mt-4 text-gray-600">
                            {query ? 'Searching with AI...' : 'Loading listings...'}
                        </p>
                    </div>
                ) : listings.length > 0 ? (
                    <>
                        <p className="text-sm text-gray-500 mb-4">
                            Found {listings.length} {listings.length === 1 ? 'property' : 'properties'}
                        </p>
                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
                            {listings.map(listing => (
                                <ListingCard key={listing.id} RealEstateListing={listing} />
                            ))}
                        </div>
                    </>
                ) : (
                    <div className="text-center py-12">
                        <svg className="w-16 h-16 text-gray-300 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                        </svg>
                        <p className="text-gray-500 mb-2">No listings found</p>
                        {query && (
                            <p className="text-sm text-gray-400">Try a different search query</p>
                        )}
                    </div>
                )}
            </div>
        </main>
    );
}