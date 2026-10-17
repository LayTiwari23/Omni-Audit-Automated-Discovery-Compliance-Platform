// FILE: src/components/Loading.jsx

import React from 'react';

const Loading = ({ message = 'Loading...', fullScreen = false }) => {
  if (fullScreen) {
    return (
      <div className="fixed inset-0 bg-gray-900 bg-opacity-50 flex items-center justify-center z-50">
        <div className="bg-white rounded-lg p-8 flex flex-col items-center space-y-4">
          <div className="spinner"></div>
          <p className="text-gray-700 font-medium">{message}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center justify-center py-12">
      <div className="spinner"></div>
      <p className="mt-4 text-gray-600">{message}</p>
    </div>
  );
};

export default Loading;
