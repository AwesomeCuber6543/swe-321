"use client"; //to save input
import React, {useState, useEffect} from 'react';

//UI Component - search feature
//Reuse of the search bar in ./HeroSplit.jx
const SearchBar = () =>  {
  return (
    <div className="flex items-center bg-blue-600 rounded-full shadow-md w-[700px] px-4 py-3 
                    transition duration-300 transform hover:scale-[1.01] cursor-pointer">
        {/* Search Bar Input */}
        <input
            type="text"
            placeholder="e.g., single-story home with hardwood floors"
            className="flex-grow text-white placeholder-white/80 bg-transparent focus:outline-none text-center"
        />
        <svg
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
                strokeWidth="2"
                stroke="white"
                className="w-5 h-5 ml-2"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="m21 21-4.35-4.35M11 19a8 8 0 1 1 0-16 8 8 0 0 1 0 16z"
                />
              </svg>
    </div>
  );
}

export default SearchBar;
