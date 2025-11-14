# Real Estate Listings API with ColPali Multi-Modal Search

## Overview

This API provides complete CRUD operations for real estate listings with advanced **multimodal search** powered by ColPali. Users can search for properties using natural language queries like "modern 3 bedroom house with a pool" and the system will match against both text descriptions and visual features in listing images.

## Features

- ✅ **Create Listings** with multiple images
- ✅ **Automatic ColPali Indexing** for visual search
- ✅ **Natural Language Search** across text and images
- ✅ **Saved Listings** (favorites) for authenticated users
- ✅ **Full CRUD Operations** with authorization
- ✅ **Filter by** price, location, property type, etc.

---

## Database Tables

### `listings`
- `id` - Auto-incrementing primary key
- `title` - Listing title
- `description` - Full description
- `property_type` - Type (house, apartment, condo, etc.)
- `listing_type` - "rent" or "buy"
- `price` - Price in decimal
- `address`, `city`, `state`, `zip_code` - Location
- `bedrooms`, `bathrooms`, `square_feet`, `year_built` - Property details
- `owner_email` - Foreign key to users table
- `colpali_index_id` - ColPali index identifier
- `created_at`, `updated_at` - Timestamps

### `listing_images`
- `id` - Auto-incrementing primary key
- `listing_id` - Foreign key to listings
- `image_data` - LONGBLOB for binary image data
- `image_order` - Display order
- `caption` - Optional image caption
- `created_at` - Timestamp

### `saved_listings`
- `id` - Auto-incrementing primary key
- `user_email` - Foreign key to users
- `listing_id` - Foreign key to listings
- `saved_at` - Timestamp

---

## API Endpoints

All listing endpoints are prefixed with `/api`

### Authentication Required Endpoints
🔐 Requires: `Authorization: Bearer <access_token>` header

---

## 📝 Create a Listing

**POST** `/api/listings`

**Auth:** Required

**Request Body:**
```json
{
  "title": "Beautiful Modern Home",
  "description": "Stunning 3 bedroom house with pool and garden",
  "property_type": "house",
  "listing_type": "buy",
  "price": 450000.00,
  "address": "123 Main St",
  "city": "Arlington",
  "state": "VA",
  "zip_code": "22201",
  "bedrooms": 3,
  "bathrooms": 2.5,
  "square_feet": 2400,
  "year_built": 2018,
  "images": [
    {
      "image_data": "base64_encoded_image_here...",
      "caption": "Front view",
      "image_order": 0
    },
    {
      "image_data": "base64_encoded_image_here...",
      "caption": "Kitchen",
      "image_order": 1
    }
  ]
}
```

**Response:** `201 Created`
```json
{
  "id": 1,
  "title": "Beautiful Modern Home",
  "description": "Stunning 3 bedroom house with pool and garden",
  "property_type": "house",
  "listing_type": "buy",
  "price": 450000.00,
  "owner_email": "user@example.com",
  "colpali_index_id": "listing_1",
  "created_at": "2025-11-14T12:00:00",
  "updated_at": "2025-11-14T12:00:00",
  "images": [...]
}
```

**Notes:**
- Images are automatically indexed by ColPali for visual search
- Images must be base64 encoded
- Accepts JPEG, PNG, GIF formats

---

## 🔍 Get Single Listing

**GET** `/api/listings/{listing_id}`

**Auth:** Not required

**Example:** `/api/listings/1`

**Response:** `200 OK`
```json
{
  "id": 1,
  "title": "Beautiful Modern Home",
  "property_type": "house",
  "listing_type": "buy",
  "price": 450000.00,
  "bedrooms": 3,
  "bathrooms": 2.5,
  "images": [
    {
      "id": 1,
      "listing_id": 1,
      "image_data": "base64_encoded...",
      "caption": "Front view",
      "image_order": 0
    }
  ]
}
```

---

## 📋 List All Listings (with filters)

**GET** `/api/listings`

**Auth:** Not required

**Query Parameters:**
- `listing_type` - Filter by "rent" or "buy"
- `property_type` - Filter by type (house, apartment, etc.)
- `city` - Filter by city
- `min_price` - Minimum price
- `max_price` - Maximum price
- `limit` - Number of results (default: 50)
- `offset` - Pagination offset (default: 0)

**Example:**
```
GET /api/listings?listing_type=buy&city=Arlington&min_price=300000&max_price=500000&limit=20
```

**Response:** `200 OK`
```json
[
  {
    "id": 1,
    "title": "Beautiful Modern Home",
    "listing_type": "buy",
    "price": 450000.00,
    "city": "Arlington",
    "images": [...]
  }
]
```

---

## 🗑️ Delete Listing

**DELETE** `/api/listings/{listing_id}`

**Auth:** Required (owner only)

**Example:** `DELETE /api/listings/1`

**Response:** `204 No Content`

**Notes:**
- Only the owner can delete their listing
- Automatically deletes associated images and ColPali index
- Cascade deletes saved listings references

---

## 🔎 Natural Language Search (ColPali-Powered)

**POST** `/api/search/natural`

**Auth:** Not required

**Request Body:**
```json
{
  "query": "modern 3 bedroom house with a pool and hardwood floors",
  "listing_type": "buy",
  "k": 10
}
```

**Parameters:**
- `query` (string, required) - Natural language search query
- `listing_type` (string, optional) - Filter by "rent" or "buy"
- `k` (int, optional) - Number of results to return (default: 10)

**Response:** `200 OK`
```json
[
  {
    "listing": {
      "id": 1,
      "title": "Beautiful Modern Home",
      "description": "...",
      "images": [...]
    },
    "relevance_score": 0.95,
    "matched_image_id": 2
  }
]
```

**How it works:**
1. Query is processed by ColPali model
2. Semantic similarity computed against indexed listing images
3. Results ranked by relevance score
4. Returns listings with their most relevant images

**Example Queries:**
- "spacious apartment with city view"
- "cozy cottage with fireplace"
- "modern kitchen with stainless steel appliances"
- "house with large backyard for kids"

---

## ❤️ Save a Listing (Add to Favorites)

**POST** `/api/saved-listings`

**Auth:** Required

**Request Body:**
```json
{
  "listing_id": 1
}
```

**Response:** `201 Created`
```json
{
  "id": 1,
  "user_email": "user@example.com",
  "listing_id": 1,
  "saved_at": "2025-11-14T12:00:00",
  "listing": {
    "id": 1,
    "title": "Beautiful Modern Home",
    "images": [...]
  }
}
```

---

## 📚 Get Saved Listings

**GET** `/api/saved-listings`

**Auth:** Required

**Response:** `200 OK`
```json
[
  {
    "id": 1,
    "user_email": "user@example.com",
    "listing_id": 1,
    "saved_at": "2025-11-14T12:00:00",
    "listing": {
      "id": 1,
      "title": "Beautiful Modern Home",
      "price": 450000.00,
      "images": [...]
    }
  }
]
```

---

## 💔 Remove Saved Listing

**DELETE** `/api/saved-listings/{listing_id}`

**Auth:** Required

**Example:** `DELETE /api/saved-listings/1`

**Response:** `204 No Content`

---

## 🧪 Testing with cURL

### 1. Create a test listing

```bash
# Login first
ACCESS_TOKEN=$(curl -s -X POST http://localhost:8001/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}' \
  | jq -r '.access_token')

# Create listing with base64 image
curl -X POST http://localhost:8001/api/listings \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Cozy Studio Apartment",
    "description": "Perfect for students or young professionals",
    "property_type": "apartment",
    "listing_type": "rent",
    "price": 1500.00,
    "city": "Fairfax",
    "bedrooms": 1,
    "bathrooms": 1,
    "images": [
      {
        "image_data": "'$(base64 -i /path/to/image.jpg)'",
        "caption": "Living area",
        "image_order": 0
      }
    ]
  }'
```

### 2. Natural language search

```bash
curl -X POST http://localhost:8001/api/search/natural \
  -H "Content-Type: application/json" \
  -d '{
    "query": "affordable apartment near university",
    "listing_type": "rent",
    "k": 5
  }' | jq
```

### 3. Save a listing

```bash
curl -X POST http://localhost:8001/api/saved-listings \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"listing_id": 1}'
```

### 4. Get saved listings

```bash
curl http://localhost:8001/api/saved-listings \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq
```

---

## 🚀 Installation

1. **Install dependencies:**
```bash
pip install -r requirements.txt
```

2. **Start the backend:**
```bash
cd backend
./start.sh
```

3. **API will be available at:**
- Base URL: `http://localhost:8001`
- API Docs: `http://localhost:8001/docs`
- ReDoc: `http://localhost:8001/redoc`

---

## 🔧 ColPali Configuration

The ColPali service automatically:
- Downloads the `vidore/colpali-v1.2` model on first use
- Creates indexes in `.colpali_indexes/` directory
- Indexes images when listings are created
- Cleans up indexes when listings are deleted

**Requirements:**
- Minimum 8GB RAM recommended
- GPU optional but recommended for faster indexing

---

## 📊 API Response Codes

- `200 OK` - Success
- `201 Created` - Resource created
- `204 No Content` - Success (no body)
- `400 Bad Request` - Invalid input
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Not authorized
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error

---

## 🔐 Authentication

All protected endpoints require JWT bearer token:

```bash
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Get token from `/login` endpoint.

---

## 💡 Tips

1. **Image Size:** Keep images under 5MB for optimal performance
2. **Search Queries:** More specific queries yield better results
3. **Batch Operations:** Index multiple listings off-peak hours
4. **Monitoring:** Check ColPali index stats regularly

---

## 🐛 Troubleshooting

**ColPali model not loading?**
- Ensure you have enough RAM (8GB+)
- Check internet connection (model downloads on first use)
- Install with: `pip install byaldi`

**Images not indexing?**
- Verify images are valid base64
- Check image format (JPEG, PNG, GIF supported)
- Review backend logs for errors

**Search returning no results?**
- Ensure listings are indexed (check `colpali_index_id` field)
- Try broader search queries
- Verify ColPali service is running

---

## 📞 Support

For issues or questions, refer to:
- API Documentation: `http://localhost:8001/docs`
- ColPali GitHub: https://github.com/AnswerDotAI/byaldi
- Backend logs: Check console output

