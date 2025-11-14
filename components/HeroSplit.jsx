// components/HeroSplit.jsx

import React from "react";
import Image from "next/image";
import NavBar from "./NavBar";


const HeroSplit = () => {
  return (
    // 1. Main container for the entire hero section
    <div className="flex flex-col h-screen bg-white"> 
      {/* ===  TOP NAVIGATION === */}    
      <NavBar/>
      {/*SPLIT CONTENT */}
      <div className="flex flex-grow"> 
          
        {/* === Left Side: Image === */}
        <div className="relative w-1/2 h-full overflow-hidden">
          <Image
            src="/images/split-hero.jpg"
            alt="Modern staircase with city view"
            fill
            className="object-cover object-center"
            priority
            quality={100}
          />
        </div>

        {/* === Right side - content */}
        <div className="w-1/2 flex flex-col justify-center px-20 bg-white text-center">
          
          {/* Main text */}
          <div className="max-w-xl mx-auto">
            <h1 className="text-6xl font-extrabold text-blue-800 leading-tight mb-6">
              Find Your Home. Live Your Lifestyle.
            </h1>
            <p className="text-gray-600 text-xl mb-12">
              Tell us what you want, we’ll find it.
            </p>

            {/* Search bar */}
            <div className="flex items-center bg-blue-600 rounded-full shadow-md w-[500px] px-4 py-3 
                          transition duration-300 transform hover:scale-[1.01] cursor-pointer mx-auto">
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
          </div>
        </div>
      </div>
      
    </div> // End of Main container
  );
};

export default HeroSplit;