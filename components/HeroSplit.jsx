'use client';

import Image from "next/image";
import { useRouter } from "next/navigation";
import { useState } from "react";
import NavBar from "./NavBar";

const HeroSplit = () => {
  const [searchQuery, setSearchQuery] = useState("");
  const router = useRouter();

  const handleSearch = (e) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      router.push(`/Search_Browse?q=${encodeURIComponent(searchQuery)}`);
    }
  };

  return (
    <div className="flex flex-col min-h-screen bg-white"> 
      <NavBar />
      <div className="flex flex-grow flex-col md:flex-row"> 
        <div className="relative w-full md:w-1/2 h-64 md:h-full">
          <Image
            src="/images/split-hero.jpg"
            alt="Modern staircase with city view"
            fill
            className="object-cover"
            priority
          />
        </div>

        <div className="w-full md:w-1/2 flex flex-col justify-center px-8 md:px-20 py-12 bg-white">
          <div className="max-w-xl mx-auto">
            <h1 className="text-4xl md:text-5xl font-bold text-gray-900 leading-tight mb-4">
              Find Your Dream Home
            </h1>
            <p className="text-gray-600 text-lg mb-8">
              Search for properties using natural language
            </p>

            <form onSubmit={handleSearch} className="relative">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Try: 3 bedroom house with modern kitchen"
                className="w-full px-6 py-4 pr-12 rounded-lg border border-gray-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 focus:outline-none transition-all"
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
          </div>
        </div>
      </div>
    </div>
  );
};

export default HeroSplit;