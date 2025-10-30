// app/page.jsx

// 1. IMPORT the component that contains your split-screen design
import HeroSplit from '../components/HeroSplit'; 

export default function Home() {
  return (
    <main>
      {/* 2. PLACE the component inside the <main> tag to render it */}
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