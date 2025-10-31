import React from 'react';
import Image from "next/image";

//UI Component - information of the listing in a card format
const ListingCard = ({RealEstateListing}) =>  {
  return (
    <div className="card rounded-lg shadow-lg overflow-hidden hover:shadow-2xl transition-shadow duration-500">
        <div className="relative h-48 w-full">
            <Image 
                src={RealEstateListing.image_urls[0]} //TODO: Change this to gallery of images
                fill
                style={{objectFit: "cover"}}
                alt={'Image of ${RealEstateListing.title_name}'}
                className="rounded-t-lg"

            />
        </div>
        <div className="container p-2">
            <h3 className="text-xl font-bold">${RealEstateListing.price}</h3>
            <p className="text-m font-semibold">{RealEstateListing.title_name}</p>
            <p>{RealEstateListing.address}</p>
        </div>
    </div>
  );
}

export default ListingCard;