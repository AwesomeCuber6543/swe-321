import NavBar from "../../components/NavBar";
import ListingCard from "../../components/ListingCard";
import SearchBar from "../../components/SearchBar";

//run: json-server --watch ./_mock_data/db.json --port 4000
//to run the mock data
async function getListing(){
    // fetch the relevant listings
    try {
        const results = await fetch("http://localhost:4000/listings");
        return results.json();
    } catch (err) {
        console.error(err)
    }
}

export default async function Search_Browse() {
    const listings = await getListing();

    return (
        <main>
            <NavBar/>
            {/* Search, Filter, and Sort Functionalities */}
            <div className="py-3 px-8 flex items-center gap-125 border border-gray-300">
                <SearchBar/>
                <div className="flex gap-5">
                    <button className="flex items-center bg-white text-blue-600 rounded-full border 
                            border-blue-600 shadow-md w-[90px] px-4 py-3 hover:scale-[1.01] duration-300">
                            Sort By
                    </button> {/* TODO: Make Sort By Dropdown Button Component */}
                    <button className="flex items-center bg-white text-blue-600 rounded-full border 
                            border-blue-600 shadow-md w-[95px] px-4 py-3 hover:scale-[1.01] duration-300">
                            Filter By
                    </button> {/* TODO: Make Filter Dropdown Button Component*/}
                </div>
            </div>
            {/* Listing Cards */}
            <div className="max-w-10xl mx-auto sm:px-6 lg:px-8 py-7"> 
                <div className="grid grid-cols-4 gap-7">
                    {listings.map(listing => (
                        <ListingCard key={listing.id} RealEstateListing={listing}/>
                    ))}
                </div>
            </div>
        </main>
    );
}