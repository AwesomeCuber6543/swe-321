"use client";

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

const SearchBar = ({ initialQuery = "" }) => {
  const [query, setQuery] = useState(initialQuery ?? "");
  const router = useRouter();

  useEffect(() => {
    setQuery(initialQuery ?? "");
  }, [initialQuery]);

  const handleSearch = (e) => {
    e.preventDefault();
    if (query.trim()) {
      router.push(`/Search_Browse?q=${encodeURIComponent(query)}`);
    }
  };

  return (
    <form onSubmit={handleSearch} className="relative w-full">
      <input
        type="text"
        value={query ?? ""}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Try: 3 bedroom house with modern kitchen"
        className="w-full px-4 py-3 pr-12 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 focus:outline-none transition-all"
      />
      <button
        type="submit"
        className="absolute right-2 top-1/2 -translate-y-1/2 bg-blue-600 text-white p-2 rounded-lg hover:bg-blue-700 transition-colors"
      >
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="m21 21-4.35-4.35M11 19a8 8 0 1 1 0-16 8 8 0 0 1 0 16z" />
        </svg>
      </button>
    </form>
  );
}

export default SearchBar;
