from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class ListingImageCreate(BaseModel):
    image_data: str
    caption: Optional[str] = None
    image_order: int = 0

class ListingImage(BaseModel):
    id: int
    listing_id: int
    image_data: str
    caption: Optional[str] = None
    image_order: int
    created_at: datetime

class ListingCreate(BaseModel):
    title: str
    description: Optional[str] = None
    property_type: str
    listing_type: str
    price: float
    address: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    zip_code: Optional[str] = None
    bedrooms: Optional[int] = None
    bathrooms: Optional[float] = None
    square_feet: Optional[int] = None
    year_built: Optional[int] = None
    images: List[ListingImageCreate] = []

class Listing(BaseModel):
    id: int
    title: str
    description: Optional[str] = None
    property_type: str
    listing_type: str
    price: float
    address: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    zip_code: Optional[str] = None
    bedrooms: Optional[int] = None
    bathrooms: Optional[float] = None
    square_feet: Optional[int] = None
    year_built: Optional[int] = None
    owner_email: str
    colpali_index_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    images: List[ListingImage] = []

class ListingSearchResult(BaseModel):
    listing: Listing
    relevance_score: float
    matched_image_id: Optional[int] = None

class SavedListingCreate(BaseModel):
    listing_id: int

class SavedListing(BaseModel):
    id: int
    user_email: str
    listing_id: int
    saved_at: datetime
    listing: Optional[Listing] = None

