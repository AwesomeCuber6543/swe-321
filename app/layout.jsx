
import "./globals.css";

export const metadata = {
  title: "Real Estate Site",
  description: "Find your new home!", 
};

// 3. Define the RootLayout component (plain JavaScript)
export default function RootLayout({ children }) {
  return (
    <html lang="en">
      {/* 4. Add the bg-white class and remove the font variables */}
      <body className="bg-white text-gray-800 antialiased min-h-screen"> 
        {children}
      </body>
    </html>
  );
}