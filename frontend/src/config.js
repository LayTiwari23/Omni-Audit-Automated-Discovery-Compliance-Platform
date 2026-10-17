// FILE: src/config.js

// Backend API configuration
const config = {
  API_BASE_URL: import.meta.env.VITE_API_BASE_URL || 'http://172.16.200.146:5000',
};

export default config;
