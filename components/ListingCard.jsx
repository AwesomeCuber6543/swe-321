'use client'
import React from 'react';
import Image from 'next/image';
import ListingModal from './ListingModal';
import ImageGallery from './ImageGallery';

//UI Component - information of the listing in a card format
const ListingCard = ({RealEstateListing}) =>  {
  const [showListingModal, setShowListingModal] = React.useState(false);

  return (
    <div>
      <div>
        <div className="card rounded-lg shadow-lg overflow-hidden hover:shadow-2xl transition-shadow duration-500">
            
            {/* Gallery of Listing Image */}
            <ImageGallery images={RealEstateListing.image_urls}/>

            {/* Short Listing Description*/}
            <div className="container p-2 cursor-pointer" onClick={() => setShowListingModal(true)}>
                <h3 className="text-xl font-bold">${RealEstateListing.price}</h3>
                <p className="text-m font-semibold">{RealEstateListing.title_name}</p>
                <p>{RealEstateListing.address}</p>
            </div>
        </div>
      </div>

      {/* Incorporates the Modal Component when Card is Clicked */}
      <ListingModal
        isOpen={showListingModal}
        onClose={() => setShowListingModal(false)}
        RealEstateListing={RealEstateListing}
      />
    </div>
  );
}

export default ListingCard;