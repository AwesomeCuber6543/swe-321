import React from 'react'

const NavBar = () =>  {
  return (
    <div>
    {/* ===  TOP NAVIGATION === */}
      <nav className="flex justify-between items-center px-16 py-6 text-base font-semibold">
        {/* Left Nav Links (Home, Buy, Rent...) */}
        <div className="flex space-x-8">
            <a href="/" className="text-blue-600 hover:text-blue-800 transition-colors transform hover:scale-105 duration-200">Home</a>
            <a href="/Buy" className="text-blue-600 hover:text-blue-800 transition-colors transform hover:scale-105 duration-200">Buy</a>
            <a href="/Rent" className="text-blue-600 hover:text-blue-800 transition-colors transform hover:scale-105 duration-200">Rent</a>
            <a href="/Search_Browse" className="text-blue-600 hover:text-blue-800 transition-colors transform hover:scale-105 duration-200">Search / Browse</a>
        </div>
        
        {/* Right Nav Links (Saved Listings, Login/Sign Up) */}
        <div>
            <a href="#" className="text-gray-600 hover:text-blue-800 mr-4 transition-colors transform hover:scale-105 duration-200">Saved Listings</a>
            <button className="bg-blue-600 text-white px-5 py-2 rounded-full text-base font-semibold hover:bg-blue-700 transition-colors transform hover:scale-105 duration-200">
                Login / Sign Up
            </button>
        </div>
      </nav>
    </div>
  );
}

export default NavBar;
