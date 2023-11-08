// content.js

// Function to add a red border to all images on the webpage
function addRedBorderToImages() {
    const images = document.querySelectorAll('img');
    images.forEach((image) => {
      image.style.border = '2px solid red';
    });
  }
  
  // Execute the function when the page is fully loaded
  window.addEventListener('load', addRedBorderToImages);
  