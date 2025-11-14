import React from 'react';
import Image from 'next/image';

//UI Component - pop-up detailed information of the listing 
const ListingModal = ({isOpen, onClose, RealEstateListing}) =>  {
  if (!isOpen) 
    return null;

  return (
    <div>
      {/* Blurred Background */}
      <div className="fixed z-100 top-0 left-0 w-full h-200 backdrop-blur-xs"></div>

      {/* Actual Modal */}
      <div className="fixed z-200 top-0 left-35 w-300 h-200 shadow-lg bg-white rounded-lg" 
          onClick={onClose}>
        <div onClick={(e) => e.stopPropagation()}>

          {/* Top Navigation Bar of the Modal - Includes Close Modal, Share, and Save Button*/}
          <nav className="flex justify-end-safe py-5 shadow-md">
            <div className="space-x-20 pr-5">
              <button className="font-bold text-blue-600 hover:text-blue-800 hover:scale-105 duration-200">Save</button>
              <button className="font-bold text-blue-600 hover:text-blue-800 hover:scale-105 duration-200">Share</button>
              <button className="w-8 rounded-md font-bold border border-blue-600 text-blue-600 hover:text-blue-800 hover:scale-105 duration-200" 
                      onClick={onClose}>X</button>
            </div>
          </nav>

          {/* Scrollable Content in Modal */}
          <div className="overflow-auto overscroll-contain">
            <div className="relative p-10 justify-center w-3/4 h-100">
              {/* Listing Image */}
              <Image 
                src={RealEstateListing.image_urls[0]} //TODO: Change this to gallery of images
                fill
                style={{objectFit: "cover"}}
                alt={'Image of ${RealEstateListing.title_name}'}
                className="rounded-t-lg pt-5"
              />
            </div>

            {/* Listing Description */}
            <div className="container p-10">
                <h1 className="text-xl font-bold">{RealEstateListing.title_name}</h1>
                <h2 className="text-m font-semibold">${RealEstateListing.price}</h2>
                <p className="text-m font-semibold text-gray">{RealEstateListing.address}</p>
                <p>{RealEstateListing.description}</p>
                <p>Upload Date: {RealEstateListing.upload_date}</p>  
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ListingModal;