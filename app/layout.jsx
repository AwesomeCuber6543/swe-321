
import "./globals.css";

export const metadata = {
  title: "Real Estate Site",
  description: "Find your new home!", 
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      {}
      <body className="bg-white text-gray-800 antialiased min-h-screen"> 
        {children}
      </body>
    </html>
  );
}