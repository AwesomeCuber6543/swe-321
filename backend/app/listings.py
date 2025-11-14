from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional
import base64
from datetime import datetime
from app.database import Database, get_db
from app.auth import get_current_user
from schemas.models import User
from schemas.listings import (
    ListingCreate, Listing, ListingImage,
    ListingSearchResult, SavedListing, SavedListingCreate
)
from app.colpali_service import colpali_service
import pymysql.cursors
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/listings", response_model=Listing, status_code=status.HTTP_201_CREATED)
async def create_listing(
    listing: ListingCreate,
    current_user: User = Depends(get_current_user),
    db_connection = Depends(get_db)
):
    """Create a new real estate listing with images and ColPali indexing."""
    db = Database(db_connection)
    cursor = db.connection.cursor()
    
    try:
        sql = """
        INSERT INTO listings (
            title, description, property_type, listing_type, price,
            address, city, state, zip_code, bedrooms, bathrooms,
            square_feet, year_built, owner_email
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(sql, (
            listing.title, listing.description, listing.property_type,
            listing.listing_type, listing.price, listing.address,
            listing.city, listing.state, listing.zip_code,
            listing.bedrooms, listing.bathrooms, listing.square_feet,
            listing.year_built, current_user.email
        ))
        listing_id = cursor.lastrowid
        
        image_ids = []
        for img in listing.images:
            img_sql = """
            INSERT INTO listing_images (listing_id, image_data, caption, image_order)
            VALUES (%s, %s, %s, %s)
            """
            image_binary = base64.b64decode(img.image_data)
            cursor.execute(img_sql, (listing_id, image_binary, img.caption, img.image_order))
            image_ids.append(cursor.lastrowid)
        
        db.connection.commit()
        
        if listing.images:
            try:
                images_for_indexing = [
                    {
                        "data": img.image_data,
                        "image_id": img_id,
                        "image_order": img.image_order
                    }
                    for img, img_id in zip(listing.images, image_ids)
                ]
                colpali_service.add_listing_images(listing_id, images_for_indexing)
            except Exception as e:
                logger.warning(f"⚠️  ColPali indexing failed: {e}")
        
        return await get_listing(listing_id, db_connection)
        
    except Exception as e:
        db.connection.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create listing: {str(e)}")
    finally:
        cursor.close()


@router.get("/listings/{listing_id}", response_model=Listing)
async def get_listing(listing_id: int, db_connection = Depends(get_db)):
    """Get a specific listing by ID with images."""
    db = Database(db_connection)
    cursor = db.connection.cursor(pymysql.cursors.DictCursor)
    
    try:
        cursor.execute("SELECT * FROM listings WHERE id = %s", (listing_id,))
        listing_data = cursor.fetchone()
        
        if not listing_data:
            raise HTTPException(status_code=404, detail="Listing not found")
        
        cursor.execute(
            "SELECT id, listing_id, image_data, caption, image_order, created_at "
            "FROM listing_images WHERE listing_id = %s ORDER BY image_order",
            (listing_id,)
        )
        images_data = cursor.fetchall()
        
        images = []
        for img in images_data:
            images.append(ListingImage(
                id=img['id'],
                listing_id=img['listing_id'],
                image_data=base64.b64encode(img['image_data']).decode('utf-8'),
                caption=img['caption'],
                image_order=img['image_order'],
                created_at=img['created_at']
            ))
        
        listing_data['images'] = images
        return Listing(**listing_data)
        
    finally:
        cursor.close()


@router.get("/listings", response_model=List[Listing])
async def get_listings(
    listing_type: Optional[str] = None,
    property_type: Optional[str] = None,
    city: Optional[str] = None,
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    limit: int = 50,
    offset: int = 0,
    current_user: User = Depends(get_current_user),
    db_connection = Depends(get_db)
):
    """Get listings with optional filters."""
    db = Database(db_connection)
    cursor = db.connection.cursor(pymysql.cursors.DictCursor)
    
    try:
        query = "SELECT * FROM listings WHERE 1=1"
        params = []
        
        if listing_type:
            query += " AND listing_type = %s"
            params.append(listing_type)
        if property_type:
            query += " AND property_type = %s"
            params.append(property_type)
        if city:
            query += " AND city = %s"
            params.append(city)
        if min_price:
            query += " AND price >= %s"
            params.append(min_price)
        if max_price:
            query += " AND price <= %s"
            params.append(max_price)
        
        query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        listings_data = cursor.fetchall()
        
        listings = []
        for listing_data in listings_data:
            listing = await get_listing(listing_data['id'], db_connection)
            listings.append(listing)
        
        return listings
        
    finally:
        cursor.close()


@router.delete("/listings/{listing_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_listing(
    listing_id: int,
    current_user: User = Depends(get_current_user),
    db_connection = Depends(get_db)
):
    """Delete a listing (owner only)."""
    db = Database(db_connection)
    cursor = db.connection.cursor(pymysql.cursors.DictCursor)
    
    try:
        cursor.execute(
            "SELECT * FROM listings WHERE id = %s",
            (listing_id,)
        )
        listing = cursor.fetchone()
        
        if not listing:
            raise HTTPException(status_code=404, detail="Listing not found")
        
        if listing['owner_email'] != current_user.email:
            raise HTTPException(status_code=403, detail="Not authorized to delete this listing")
        
        colpali_service.remove_listing_from_index(listing_id)
        
        cursor.execute("DELETE FROM listings WHERE id = %s", (listing_id,))
        db.connection.commit()
        
    finally:
        cursor.close()


@router.post("/search/natural", response_model=List[ListingSearchResult])
async def natural_language_search(
    query: str,
    listing_type: Optional[str] = None,
    k: int = 10,
    db_connection = Depends(get_db)
):
    """Search listings using natural language queries via ColPali."""
    logger.info(f"🔍 Natural language search request - Query: '{query}', Type: {listing_type}, k: {k}")
    
    try:
        logger.info(f"🤖 Calling ColPali search service...")
        search_results = colpali_service.search(query=query, k=k * 2)
        
        if not search_results:
            logger.warning("⚠️  No search results. Index may be empty.")
            return []
            
        logger.info(f"✅ ColPali returned {len(search_results)} results")
        
        db = Database(db_connection)
        cursor = db.connection.cursor(pymysql.cursors.DictCursor)
        
        filter_query = "SELECT id FROM listings WHERE 1=1"
        params = []
        if listing_type:
            filter_query += " AND listing_type = %s"
            params.append(listing_type)
        
        cursor.execute(filter_query, params)
        valid_listing_ids = set(row['id'] for row in cursor.fetchall())
        cursor.close()
        
        results = []
        seen_listings = set()
        
        for result in search_results:
            listing_id = result.get('listing_id')
            
            if not listing_id or listing_id in seen_listings:
                continue
                
            if listing_type and listing_id not in valid_listing_ids:
                continue
                
            seen_listings.add(listing_id)
            
            try:
                logger.info(f"📄 Fetching listing {listing_id}")
                listing = await get_listing(listing_id, db_connection)
                results.append(ListingSearchResult(
                    listing=listing,
                    relevance_score=result['score'],
                    matched_image_id=None
                ))
                
                if len(results) >= k:
                    break
            except Exception as listing_error:
                logger.error(f"❌ Error fetching listing {listing_id}: {listing_error}", exc_info=True)
                continue
        
        logger.info(f"✅ Returning {len(results)} search results")
        return results
        
    except Exception as e:
        logger.error(f"❌ Search failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@router.post("/saved-listings", response_model=SavedListing, status_code=status.HTTP_201_CREATED)
async def save_listing(
    saved_listing: SavedListingCreate,
    current_user: User = Depends(get_current_user),
    db_connection = Depends(get_db)
):
    """Save a listing to user's favorites."""
    db = Database(db_connection)
    cursor = db.connection.cursor()
    
    try:
        cursor.execute("SELECT id FROM listings WHERE id = %s", (saved_listing.listing_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Listing not found")
        
        sql = "INSERT INTO saved_listings (user_email, listing_id) VALUES (%s, %s)"
        cursor.execute(sql, (current_user.email, saved_listing.listing_id))
        saved_id = cursor.lastrowid
        db.connection.commit()
        
        cursor = db.connection.cursor(pymysql.cursors.DictCursor)
        cursor.execute(
            "SELECT * FROM saved_listings WHERE id = %s",
            (saved_id,)
        )
        saved_data = cursor.fetchone()
        saved_data['listing'] = await get_listing(saved_listing.listing_id, db_connection)
        
        return SavedListing(**saved_data)
        
    except Exception as e:
        db.connection.rollback()
        if "Duplicate entry" in str(e):
            raise HTTPException(status_code=400, detail="Listing already saved")
        raise HTTPException(status_code=500, detail=f"Failed to save listing: {str(e)}")
    finally:
        cursor.close()


@router.get("/saved-listings", response_model=List[SavedListing])
async def get_saved_listings(
    current_user: User = Depends(get_current_user),
    db_connection = Depends(get_db)
):
    """Get all saved listings for the current user."""
    db = Database(db_connection)
    cursor = db.connection.cursor(pymysql.cursors.DictCursor)
    
    try:
        cursor.execute(
            "SELECT * FROM saved_listings WHERE user_email = %s ORDER BY saved_at DESC",
            (current_user.email,)
        )
        saved_data = cursor.fetchall()
        
        results = []
        for saved in saved_data:
            saved['listing'] = await get_listing(saved['listing_id'], db_connection)
            results.append(SavedListing(**saved))
        
        return results
        
    finally:
        cursor.close()


@router.delete("/saved-listings/{listing_id}", status_code=status.HTTP_204_NO_CONTENT)
async def unsave_listing(
    listing_id: int,
    current_user: User = Depends(get_current_user),
    db_connection = Depends(get_db)
):
    """Remove a listing from saved favorites."""
    db = Database(db_connection)
    cursor = db.connection.cursor()
    
    try:
        cursor.execute(
            "DELETE FROM saved_listings WHERE user_email = %s AND listing_id = %s",
            (current_user.email, listing_id)
        )
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Saved listing not found")
        
        db.connection.commit()
        
    finally:
        cursor.close()

