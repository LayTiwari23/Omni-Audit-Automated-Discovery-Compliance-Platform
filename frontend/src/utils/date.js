/**
 * Formats a date string or object to IST (Indian Standard Time).
 */
export function formatToIST(dateInput, options = {}) {
  if (!dateInput) return '-';
  
  let date;
  if (typeof dateInput === 'string') {
    // Ensure we have a 'T' instead of space for ISO compatibility
    let cleanDate = dateInput.replace(' ', 'T');
    
    // If no timezone info, assume UTC
    if (!cleanDate.includes('Z') && !cleanDate.includes('+')) {
      cleanDate += 'Z';
    }
    date = new Date(cleanDate);
  } else {
    date = dateInput;
  }
  
  // If the string doesn't end with Z and doesn't have a timezone offset, 
  // and we know the backend sends UTC, we might need to append Z.
  // But usually new Date() on an ISO string with 'T' handles UTC correctly if 'Z' is present.
  
  const defaultOptions = {
    timeZone: 'Asia/Kolkata',
    hour12: true,
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    ...options
  };

  try {
    return new Intl.DateTimeFormat('en-IN', defaultOptions).format(date);
  } catch (e) {
    console.error("Date formatting error:", e);
    return date.toString();
  }
}

/**
 * Returns only the time part in IST.
 */
export function formatTimeIST(dateInput) {
    return formatToIST(dateInput, {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        day: undefined,
        month: undefined,
        year: undefined
    });
}

/**
 * Returns only the date part in IST.
 */
export function formatDateIST(dateInput) {
    return formatToIST(dateInput, {
        hour: undefined,
        minute: undefined,
        second: undefined
    });
}
