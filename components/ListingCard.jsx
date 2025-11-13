'use client'
import React from 'react';
import Image from 'next/image';
import ListingModal from './ListingModal';

//UI Component - information of the listing in a card format
const ListingCard = ({RealEstateListing}) =>  {
  const [showListingModal, setShowListingModal] = React.useState(false);

  return (
    <div>
      <div onClick={()=>setShowListingModal(true)} style={{cursor:'pointer'}}>
        <div className="card rounded-lg shadow-lg overflow-hidden hover:shadow-2xl transition-shadow duration-500">
            <div className="relative h-48 w-full">

              {/* Listing Image */}
                <Image 
                    src={RealEstateListing.image_urls[0]} //TODO: Change this to gallery of images
                    fill
                    style={{objectFit: "cover"}}
                    alt={'Image of ${RealEstateListing.title_name}'}
                    className="rounded-t-lg"

                />
            </div>

            {/* Short Listing Description*/}
            <div className="container p-2">
                <h3 className="text-xl font-bold">${RealEstateListing.price}</h3>
                <p className="text-m font-semibold">{RealEstateListing.title_name}</p>
                <p>{RealEstateListing.address}</p>
            </div>
        </div>
      </div>

      {/* Incorporates the Modal Component when Card is Clicked */}
      <ListingModal
        isOpen={showListingModal}
        onClose={()=>setShowListingModal(false)}
        RealEstateListing={RealEstateListing}
      />
    </div>
  );
}

export default ListingCard;