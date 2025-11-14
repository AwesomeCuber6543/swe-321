'use client'
import React from 'react';
import Image from 'next/image';

//UI Component - carousel gallery of images
const ImageGallery = ({images}) =>  {
    const [currId, setCurrId] = React.useState(0);

    //Goes forward in the carousel by setting the index, id
    const next = () => {
        setCurrId((id) => (id + 1) % images.length);
    };

    //Goes back in the carousel by setting the index, id
    const back = () => {
        setCurrId((id) => (id == 0) ? (images.length - 1) : (id - 1));
    };

    return (
        <div className="relative h-48 w-full overflow-hidden">

            {/* Current Image Displayed */}
            <div className="transition-transform ease-out duration-100">
                <Image 
                    src={images[currId]}
                    fill
                    alt={'Image {id + 1} of Real Estate Listing'}
                    className="rounded-t-lg object-cover"
                />
            </div>

            {/* Navigation Buttons: Back and Next Image */}
            <div className="absolute flex justify-between p-3 inset-0 items-center">
                <button dir="ltr" className="text-3xl text-gray-500 semi-bold rounded-s-lg bg-gray-500/25 hover:shadow-md cursor-pointer" 
                        onClick={back}>{'<'}</button>
                <button dir="rtl" className="text-3xl text-gray-500 semi-bold rounded-s-lg bg-gray-500/25 hover:shadow-md cursor-pointer" 
                        onClick={next}>{'<'}</button>
            </div> 
        </div>
    );
}


export default ImageGallery;