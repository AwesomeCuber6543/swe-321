import React from "react";
import Image from "next/image";

const LoginPage = () => {
  return (
    <div className="flex h-screen bg-white">

      {/* === Left Side: Login/Sign Up Options (50% Width) === */}
      <div className="w-1/2 flex flex-col items-center justify-center px-16">
        <div className="max-w-md w-full">
          <h1 className="text-4xl font-extrabold text-blue-800 mb-8 text-center">
            Login or Sign Up
          </h1>

          {/* Email Input */}
          <input
            type="email"
            placeholder="Email"
            className="w-full p-3 border border-gray-300 rounded-lg mb-4 focus:outline-none focus:border-blue-500"
          />

          {/* Continue with Email Button */}
          <button className="w-full bg-blue-800 text-white py-3 rounded-lg text-lg font-semibold hover:bg-blue-900 transition-colors mb-4 text-center">
            Continue
          </button>

          <div className="text-center text-gray-400 my-4">— OR —</div>

          {/* Social Login Buttons */}
          <button className="w-full flex items-center justify-center border border-gray-300 bg-white py-3 rounded-lg text-gray-700 font-semibold mb-3 hover:bg-gray-50 transition-colors">
            Continue with Google
          </button>

          <button className="w-full flex items-center justify-center border border-gray-300 bg-white py-3 rounded-lg text-gray-700 font-semibold hover:bg-gray-50 transition-colors">
            Continue with Apple
          </button>
        </div>
      </div>

      {/* === Right Side: Full-screen Home Image (50% Width) === */}
      <div className="relative w-1/2 h-full overflow-hidden">
        <Image
          src="/images/login-house.jpg"
          alt="Modern home interior"
          fill
          className="object-cover object-center"
          priority
          quality={100}
        />
      </div>

    </div>
  );
};

export default LoginPage;
