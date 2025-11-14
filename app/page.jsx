// app/page.jsx

import HeroSplit from '../components/HeroSplit'; 

export default function Home() {
  return (
    <main>
      {}
      <HeroSplit /> 
      
      {/* This is a simple placeholder for the content that will appear below the fold 
          (like the "Our Expert Services" section) 
      */}
      <section className="container mx-auto py-16 px-4">
        {/* Placeholder for service cards */}
      </section>
    </main>
  );
}