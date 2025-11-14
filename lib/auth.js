// lib/auth.js - Authentication utility functions

const API_URL = 'http://localhost:8001';

export class AuthService {
  // Register a new user
  static async register(email, password, firstName, lastName) {
    const response = await fetch(`${API_URL}/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email,
        password,
        first_name: firstName,
        last_name: lastName,
      }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Registration failed');
    }

    return response.json();
  }

  // Login user
  static async login(email, password) {
    const response = await fetch(`${API_URL}/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email,
        password,
      }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Login failed');
    }

    const data = await response.json();
    
    // Store tokens in localStorage
    this.setTokens(data.access_token, data.refresh_token);
    
    return data;
  }

  // Refresh access token
  static async refreshToken() {
    const accessToken = this.getAccessToken();
    
    if (!accessToken) {
      throw new Error('No access token found');
    }

    const response = await fetch(`${API_URL}/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        access_token: accessToken,
      }),
    });

    if (!response.ok) {
      this.clearTokens();
      throw new Error('Token refresh failed');
    }

    const data = await response.json();
    this.setTokens(data.access_token, data.refresh_token);
    
    return data;
  }

  // Make authenticated API request
  static async authenticatedFetch(url, options = {}) {
    const accessToken = this.getAccessToken();
    
    if (!accessToken) {
      throw new Error('Not authenticated');
    }

    const response = await fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${accessToken}`,
      },
    });

    // If token expired, try to refresh
    if (response.status === 401) {
      try {
        await this.refreshToken();
        // Retry the request with new token
        const newAccessToken = this.getAccessToken();
        return fetch(url, {
          ...options,
          headers: {
            ...options.headers,
            'Authorization': `Bearer ${newAccessToken}`,
          },
        });
      } catch (error) {
        this.clearTokens();
        throw new Error('Session expired. Please login again.');
      }
    }

    return response;
  }

  // Get current user info
  static async getCurrentUser() {
    const response = await this.authenticatedFetch(`${API_URL}/hello`);
    
    if (!response.ok) {
      throw new Error('Failed to get user info');
    }

    return response.json();
  }

  // Token management
  static setTokens(accessToken, refreshToken) {
    if (typeof window !== 'undefined') {
      localStorage.setItem('access_token', accessToken);
      localStorage.setItem('refresh_token', refreshToken);
    }
  }

  static getAccessToken() {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('access_token');
    }
    return null;
  }

  static getRefreshToken() {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('refresh_token');
    }
    return null;
  }

  static clearTokens() {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
    }
  }

  static isAuthenticated() {
    return !!this.getAccessToken();
  }

  static logout() {
    this.clearTokens();
  }

  static async createListing(listingData) {
    const response = await this.authenticatedFetch(`${API_URL}/api/listings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(listingData),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to create listing');
    }

    return response.json();
  }
}

