const API_URL = 'http://localhost:8001/api';

export class ListingsService {
  static async getAllListings(filters = {}) {
    const params = new URLSearchParams();
    if (filters.listing_type) params.append('listing_type', filters.listing_type);
    if (filters.property_type) params.append('property_type', filters.property_type);
    if (filters.city) params.append('city', filters.city);
    if (filters.min_price) params.append('min_price', filters.min_price);
    if (filters.max_price) params.append('max_price', filters.max_price);
    if (filters.limit) params.append('limit', filters.limit);
    if (filters.offset) params.append('offset', filters.offset);

    const url = `${API_URL}/listings${params.toString() ? '?' + params.toString() : ''}`;
    
    const token = typeof window !== 'undefined' ? localStorage.getItem('access_token') : null;
    const headers = {};
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    
    const response = await fetch(url, { headers });
    
    if (!response.ok) {
      throw new Error('Failed to fetch listings');
    }
    
    return response.json();
  }

  static async getListing(id) {
    const token = typeof window !== 'undefined' ? localStorage.getItem('access_token') : null;
    const headers = {};
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    
    const response = await fetch(`${API_URL}/listings/${id}`, { headers });
    
    if (!response.ok) {
      throw new Error('Failed to fetch listing');
    }
    
    return response.json();
  }

  static async naturalLanguageSearch(query, listingType = null, k = 10) {
    const url = `${API_URL}/search/natural?query=${encodeURIComponent(query)}&k=${k}${listingType ? `&listing_type=${listingType}` : ''}`;
    console.log(`🔍 Searching with URL: ${url}`);
    
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      }
    });
    
    console.log(`📡 Response status: ${response.status}`);
    
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      console.error('❌ Search failed:', errorData);
      throw new Error(errorData.detail || 'Search failed');
    }
    
    const data = await response.json();
    console.log(`✅ Search returned ${data.length} results`);
    return data;
  }

  static async getSavedListings(token) {
    const response = await fetch(`${API_URL}/saved-listings`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    if (!response.ok) {
      throw new Error('Failed to fetch saved listings');
    }
    
    return response.json();
  }

  static async saveListing(listingId, token) {
    const response = await fetch(`${API_URL}/saved-listings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ listing_id: listingId })
    });
    
    if (!response.ok) {
      throw new Error('Failed to save listing');
    }
    
    return response.json();
  }

  static async unsaveListing(listingId, token) {
    const response = await fetch(`${API_URL}/saved-listings/${listingId}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    if (!response.ok) {
      throw new Error('Failed to unsave listing');
    }
  }
}

