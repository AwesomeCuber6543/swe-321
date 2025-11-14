'use client'
import React from 'react';
import ListingModal from './ListingModal';

const ListingCard = ({RealEstateListing}) =>  {
  const [showListingModal, setShowListingModal] = React.useState(false);
  const firstImage = RealEstateListing.images?.[0];

  return (
    <>
      <div className="bg-white rounded-lg shadow-sm border border-gray-100 overflow-hidden hover:shadow-md transition-shadow duration-200 cursor-pointer"
           onClick={() => setShowListingModal(true)}>
        <div className="relative h-48 bg-gray-200">
          {firstImage ? (
            <img
              src={`data:image/jpeg;base64,${firstImage.image_data}`}
              alt={RealEstateListing.title}
              className="w-full h-full object-cover"
            />
          ) : (
            <div className="w-full h-full flex items-center justify-center text-gray-400">
              <svg className="w-16 h-16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
              </svg>
            </div>
          )}
        </div>
        
        <div className="p-4">
          <h3 className="text-xl font-bold text-blue-600 mb-1">
            ${RealEstateListing.price?.toLocaleString()}
          </h3>
          <p className="text-gray-900 font-medium mb-1 line-clamp-1">
            {RealEstateListing.title}
          </p>
          {RealEstateListing.address && (
            <p className="text-sm text-gray-600 line-clamp-1">{RealEstateListing.address}</p>
          )}
          {RealEstateListing.city && (
            <p className="text-sm text-gray-500">{RealEstateListing.city}, {RealEstateListing.state}</p>
          )}
          <div className="flex items-center gap-3 mt-2 text-sm text-gray-600">
            {RealEstateListing.bedrooms && (
              <span>{RealEstateListing.bedrooms} bd</span>
            )}
            {RealEstateListing.bathrooms && (
              <span>{RealEstateListing.bathrooms} ba</span>
            )}
            {RealEstateListing.square_feet && (
              <span>{RealEstateListing.square_feet?.toLocaleString()} sqft</span>
            )}
          </div>
        </div>
      </div>

      <ListingModal
        isOpen={showListingModal}
        onClose={() => setShowListingModal(false)}
        RealEstateListing={RealEstateListing}
      />
    </>
  );
}

export default ListingCard;