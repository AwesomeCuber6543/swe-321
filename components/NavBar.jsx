'use client';

import Link from 'next/link';
import { useAuth } from '../contexts/AuthContext';

const NavBar = () =>  {
  const { isAuthenticated, user, logout } = useAuth();

  return (
    <nav className="flex justify-between items-center px-8 md:px-16 py-5 text-base font-medium border-b border-gray-100 bg-white">
      <div className="flex items-center space-x-8">
        <Link href="/" className="text-xl font-bold text-blue-700 hover:text-blue-900 transition-colors">
          RealEstate
        </Link>
        <div className="hidden md:flex space-x-6">
          <Link href="/Buy" className="text-gray-700 hover:text-blue-700 transition-colors">
            Buy
          </Link>
          <Link href="/Rent" className="text-gray-700 hover:text-blue-700 transition-colors">
            Rent
          </Link>
          <Link href="/Search_Browse" className="text-gray-700 hover:text-blue-700 transition-colors">
            Browse
          </Link>
        </div>
      </div>
      
      <div className="flex items-center space-x-4">
        {isAuthenticated ? (
          <>
            <Link href="/CreateListing" className="hidden md:block text-blue-600 hover:text-blue-700 font-medium transition-colors">
              + List Property
            </Link>
            <Link href="/Dashboard" className="hidden md:block text-gray-700 hover:text-blue-700 transition-colors">
              Dashboard
            </Link>
            <span className="text-sm text-gray-600">
              {user?.user_email?.split('@')[0]}
            </span>
            <button 
              onClick={logout}
              className="bg-gray-100 text-gray-700 px-4 py-2 rounded-lg text-sm font-medium hover:bg-gray-200 transition-colors"
            >
              Logout
            </button>
          </>
        ) : (
          <Link href="/Login">
            <button className="bg-blue-600 text-white px-5 py-2 rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors shadow-sm">
              Login
            </button>
          </Link>
        )}
      </div>
    </nav>
  );
}

export default NavBar;
