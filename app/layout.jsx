
import "./globals.css";
import { AuthProvider } from "../contexts/AuthContext";

export const metadata = {
  title: "Real Estate Site",
  description: "Find your new home!", 
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body className="bg-white text-gray-800 antialiased min-h-screen"> 
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}