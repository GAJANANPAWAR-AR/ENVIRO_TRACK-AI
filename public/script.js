// public/script.js

// --- Global Variables and Constants ---
let map;
let currentMarkers = {}; // To store Leaflet circle markers
let userLocation = null; // Stores user's current latitude and longitude
let currentStream; // To hold the camera video stream
let capturedFile = null; // To store the captured image file (Blob/File object)
let currentReportId = null; // To store the ID of the currently viewed report in the popup

// Get user role and access token from browser's local storage (for municipal login)
let userRole = localStorage.getItem('userRole');
let accessToken = localStorage.getItem('accessToken');

const API_BASE_URL = '/api'; // This points to your Node.js backend API

// --- DOM Elements (Get references to HTML elements) ---
// General UI
const mapDiv = document.getElementById('map');
const showReportFormBtn = document.getElementById('showReportFormBtn');
const showLeaderboardBtn = document.getElementById('showLeaderboardBtn');
const showMunicipalLoginBtn = document.getElementById('showMunicipalLoginBtn');
const logoutBtn = document.getElementById('logoutBtn');

// Report Form
const reportFormContainer = document.getElementById('reportFormContainer');
const wasteReportForm = document.getElementById('wasteReportForm');
const wasteImageInput = document.getElementById('wasteImageInput');
const cameraFeed = document.getElementById('cameraFeed');
const canvas = document.getElementById('canvas');
const capturePhotoBtn = document.getElementById('capturePhotoBtn');
const capturedImagePreview = document.getElementById('capturedImagePreview');
const descriptionInput = document.getElementById('description');
const reportedByInput = document.getElementById('reportedBy');
const latitudeInput = document.getElementById('latitude');
const longitudeInput = document.getElementById('longitude');
const getCurrentLocationBtn = document.getElementById('getCurrentLocationBtn');

// Report Details Popup
const reportDetailsPopup = document.getElementById('reportDetailsPopup');
const popupDescription = document.getElementById('popupDescription');
const popupReportedBy = document.getElementById('popupReportedBy');
const popupReportedAt = document.getElementById('popupReportedAt');
const popupLatitude = document.getElementById('popupLatitude');
const popupLongitude = document.getElementById('popupLongitude');
const popupWasteImage = document.getElementById('popupWasteImage');
const municipalControls = document.getElementById('municipalControls'); // Container for municipal actions
const cleanReportForm = document.getElementById('cleanReportForm');
const cleanReportIdInput = document.getElementById('cleanReportId');
const cleanedImageInput = document.getElementById('cleanedImageInput');
const cleanedDetails = document.getElementById('cleanedDetails'); // Container for cleaned info
const popupCleanedBy = document.getElementById('popupCleanedBy');
const popupCleanedAt = document.getElementById('popupCleanedAt');
const popupCleanedImage = document.getElementById('popupCleanedImage');

// Municipal Login Form
const municipalLoginFormContainer = document.getElementById('municipalLoginFormContainer');
const municipalLoginForm = document.getElementById('municipalLoginForm');
const loginUsernameInput = document.getElementById('loginUsername');
const loginPasswordInput = document.getElementById('loginPassword');

// Leaderboard
const leaderboardContainer = document.getElementById('leaderboardContainer');
const leaderboardTableBody = document.querySelector('#leaderboardTable tbody');


// --- Utility Functions ---

// Hides all overlay forms
function hideAllForms() {
    reportFormContainer.style.display = 'none';
    reportDetailsPopup.style.display = 'none';
    municipalLoginFormContainer.style.display = 'none';
    leaderboardContainer.style.display = 'none';
    stopCamera(); // Ensure camera is stopped when forms are hidden
}

// Helper to show a DOM element
function showElement(element) {
    element.style.display = 'block';
}

// Helper to hide a DOM element
function hideElement(element) {
    element.style.display = 'none';
}

// Updates the visibility of login/logout buttons based on user's authentication status
function updateAuthUI() {
    if (userRole === 'municipal' && accessToken) {
        hideElement(showMunicipalLoginBtn);
        showElement(logoutBtn);
    } else {
        showElement(showMunicipalLoginBtn);
        hideElement(logoutBtn);
    }
}

// --- Map Initialization and Interaction ---

function initializeMap() {
    // Initialize map centered on a general location (e.g., India) with a zoom level
    map = L.map('map').setView([20.5937, 78.9629], 5); // Latitude, Longitude, Zoom Level

    // Add OpenStreetMap tiles to the map (free to use)
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19, // Max zoom level for these tiles
        attribution: '&copy; <a href="http://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
    }).addTo(map);

    // Try to get user's current location and center the map there
    map.locate({ setView: true, maxZoom: 16, enableHighAccuracy: true });

    // Event listener for when user's location is found
    map.on('locationfound', function(e) {
        userLocation = e.latlng; // Store location as a Leaflet LatLng object
        latitudeInput.value = userLocation.lat.toFixed(6); // Populate latitude input
        longitudeInput.value = userLocation.lng.toFixed(6); // Populate longitude input

        // Add a marker for the user's current location
        L.marker(userLocation)
            .addTo(map)
            .bindPopup("You are here!") // Popup text
            .openPopup(); // Show the popup
    });

    // Event listener for when location access fails
    map.on('locationerror', function(e) {
        console.error("Location access denied or error:", e.message);
        alert("Location access denied or error: " + e.message + ". Please enable location services or enter coordinates manually.");
    });

    fetchWasteReports(); // Load existing waste reports on the map when it loads
}

// Fetches active waste reports from the backend
async function fetchWasteReports() {
    try {
        const response = await fetch(`${API_BASE_URL}/waste-reports`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const reports = await response.json();
        renderWasteReportsOnMap(reports); // Display them on the map
    } catch (error) {
        console.error('Error fetching waste reports:', error);
        alert('Could not load waste reports.');
    }
}

// Renders fetched waste reports as red spots on the map
function renderWasteReportsOnMap(reports) {
    // Clear any existing markers/circles to avoid duplicates
    Object.values(currentMarkers).forEach(marker => map.removeLayer(marker));
    currentMarkers = {}; // Reset the storage

    reports.forEach(report => { // This is the ONLY forEach loop
        // Create a red circle marker for each waste report
        const circleMarker = L.circleMarker([report.latitude, report.longitude], {
            radius: 12, // Size of the spot (adjust as needed)
            fillColor: 'red',
            color: 'darkred', // Border color
            weight: 2,
            opacity: 0.8,
            fillOpacity: 0.8,
            interactive: true, // Make it clickable
        }).addTo(map);

        // Attach the report ID directly to the marker object itself
        circleMarker.reportId = report.id;

        // When the circle marker is clicked, show its details
        // The event handler receives the event object (e)
        circleMarker.on('click', (e) => {
            // Access the reportId that we attached to the clicked marker (e.target)
            showReportDetails(e.target.reportId);
        });

        currentMarkers[report.id] = circleMarker; // Store marker by report ID for easy removal/update
    });
}

// Shows a popup with detailed information about a specific waste report
async function showReportDetails(reportId) {
    hideAllForms(); // Hide any other open forms first
    try {
        // Corrected fetch URL, removed HTML tags
        const response = await fetch(`${API_BASE_URL}/waste-reports/${reportId}`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const report = await response.json();

        currentReportId = report.id; // Save this ID for potential cleaning action

        // Populate the popup with report data
        popupDescription.textContent = report.description || 'No description provided.';
        popupReportedBy.textContent = report.reported_by || 'Anonymous';
        popupReportedAt.textContent = new Date(report.reported_at).toLocaleString(); // Format date
        popupLatitude.textContent = report.latitude;
        popupLongitude.textContent = report.longitude;
        popupWasteImage.src = report.image_url;
        popupWasteImage.style.display = report.image_url ? 'block' : 'none'; // Show image if available

        // Handle municipal controls visibility
        if (userRole === 'municipal') { // Only show if a municipal user is logged in
            showElement(municipalControls);
            cleanReportIdInput.value = report.id; // Set report ID for the cleaning form
            // If report is already cleaned, show cleaned details, hide clean form
            if (report.is_cleaned) {
                hideElement(cleanReportForm);
                showElement(cleanedDetails);
                // For cleanedBy, you might want to fetch username from user ID
                popupCleanedBy.textContent = report.cleaned_by_user_id ? `User ID ${report.cleaned_by_user_id}` : 'N/A';
                popupCleanedAt.textContent = report.cleaned_at ? new Date(report.cleaned_at).toLocaleString() : 'N/A';
                popupCleanedImage.src = report.cleaned_image_url;
                popupCleanedImage.style.display = report.cleaned_image_url ? 'block' : 'none';
            } else { // If not cleaned, show clean form, hide cleaned details
                showElement(cleanReportForm);
                hideElement(cleanedDetails);
            }
        } else { // If not municipal user, hide all municipal controls
            hideElement(municipalControls);
            hideElement(cleanReportForm);
        }

        // Always display cleaned details if the report is already cleaned, regardless of user role
        if (report.is_cleaned && userRole !== 'municipal') { // Ensure it's not double-shown if municipal
            showElement(cleanedDetails);
            popupCleanedBy.textContent = report.cleaned_by_user_id ? `User ID ${report.cleaned_by_user_id}` : 'N/A';
            popupCleanedAt.textContent = report.cleaned_at ? new Date(report.cleaned_at).toLocaleString() : 'N/A';
            popupCleanedImage.src = report.cleaned_image_url;
            popupCleanedImage.style.display = report.cleaned_image_url ? 'block' : 'none';
        }

        showElement(reportDetailsPopup); // Finally show the popup
    } catch (error) {
        console.error('Error fetching report details:', error);
        alert('Could not load report details.');
    }
}


// --- Camera and Location Functions ---

// Starts the device camera and displays the feed
async function startCamera() {
    if (currentStream) { // If a stream is already active, stop it first
        stopCamera();
    }
    try {
        // Request video stream, preferring the environment (rear) camera
        const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
        cameraFeed.srcObject = stream; // Connect stream to video element
        currentStream = stream; // Store stream for later stopping

        showElement(cameraFeed); // Show the video element
        hideElement(wasteImageInput); // Hide the file input
        showElement(capturePhotoBtn); // Show the capture button
        hideElement(capturedImagePreview); // Hide previous preview
        capturedFile = null; // Reset captured file
    } catch (err) {
        console.error('Error accessing camera:', err);
        alert('Could not access camera. Please allow camera access or upload from gallery.');
        hideElement(cameraFeed); // Hide camera feed if it fails
        showElement(wasteImageInput); // Show file input as fallback
        hideElement(capturePhotoBtn); // Hide capture button
    }
}

// Stops the active camera stream
function stopCamera() {
    if (currentStream) {
        currentStream.getTracks().forEach(track => track.stop()); // Stop all tracks
        cameraFeed.srcObject = null; // Disconnect stream from video element
        currentStream = null;
        hideElement(cameraFeed);
        hideElement(capturePhotoBtn);
    }
}

// Event listener for the "Capture Photo" button
capturePhotoBtn.addEventListener('click', () => {
    // Set canvas dimensions to match the video feed
    canvas.width = cameraFeed.videoWidth;
    canvas.height = cameraFeed.videoHeight;
    // Draw the current frame from the video onto the canvas
    canvas.getContext('2d').drawImage(cameraFeed, 0, 0, canvas.width, canvas.height);

    // Convert canvas content to a Blob (image file)
    canvas.toBlob((blob) => {
        // Create a File object from the Blob
        capturedFile = new File([blob], `waste-image-${Date.now()}.jpeg`, { type: 'image/jpeg' });
        capturedImagePreview.src = URL.createObjectURL(blob); // Set preview image source
        showElement(capturedImagePreview); // Show the preview
        hideElement(cameraFeed); // Hide video feed after capture
        hideElement(capturePhotoBtn); // Hide capture button
    }, 'image/jpeg'); // Specify image format
});

// Event listener for when a file is selected via the input (e.g., from gallery)
wasteImageInput.addEventListener('change', (event) => {
    stopCamera(); // Stop camera if a file is manually selected
    const file = event.target.files[0]; // Get the selected file
    if (file) {
        capturedFile = file;
        capturedImagePreview.src = URL.createObjectURL(file); // Set preview image
        showElement(capturedImagePreview); // Show the preview
    } else {
        hideElement(capturedImagePreview);
        capturedFile = null;
    }
});

// Event listener for the "Get My Location" button
getCurrentLocationBtn.addEventListener('click', () => {
    if (navigator.geolocation) { // Check if browser supports Geolocation API
        navigator.geolocation.getCurrentPosition(position => {
            userLocation = {
                lat: position.coords.latitude,
                lng: position.coords.longitude
            };
            latitudeInput.value = userLocation.lat.toFixed(6); // Populate latitude
            longitudeInput.value = userLocation.lng.toFixed(6); // Populate longitude
            map.setView(userLocation, 16); // Center map on current location with higher zoom
        }, (error) => {
            console.error('Error getting location:', error);
            alert('Unable to retrieve your location. Please ensure location services are enabled and allowed.');
            userLocation = null;
            latitudeInput.value = '';
            longitudeInput.value = '';
        });
    } else {
        alert('Geolocation is not supported by your browser.');
        userLocation = null;
    }
});

// --- Form Submission Handlers ---

// Handles the submission of the waste report form
wasteReportForm.addEventListener('submit', async (event) => {
    event.preventDefault(); // Prevent default form submission (page reload)

    if (!capturedFile) {
        alert('Please capture an image or select one from your gallery.');
        return;
    }
    if (!latitudeInput.value || !longitudeInput.value) {
        alert('Please get your current location.');
        return;
    }

    // Create FormData object to send file and other data
    const formData = new FormData();
    formData.append('wasteImage', capturedFile); // 'wasteImage' matches multer field name in server.js
    formData.append('latitude', latitudeInput.value);
    formData.append('longitude', longitudeInput.value);
    formData.append('description', descriptionInput.value);
    formData.append('reportedBy', reportedByInput.value);

    try {
        const response = await fetch(`${API_BASE_URL}/report-waste`, {
            method: 'POST',
            body: formData, // FormData automatically sets content type
        });

        if (!response.ok) {
            const errorData = await response.json(); // Get error message from backend
            throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
        }

        const result = await response.json();
        alert('Waste reported successfully!');
        console.log('Report success:', result);
        wasteReportForm.reset(); // Clear form fields
        capturedFile = null; // Reset captured file state
        hideElement(capturedImagePreview); // Hide preview
        stopCamera(); // Stop camera after successful submission
        hideAllForms(); // Hide the report form
        fetchWasteReports(); // Refresh markers on the map to show the new report
    } catch (error) {
        console.error('Error submitting waste report:', error);
        alert('Failed to submit waste report: ' + error.message);
    }
});

// Handles municipal user login
municipalLoginForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const username = loginUsernameInput.value;
    const password = loginPasswordInput.value;

    try {
        const response = await fetch(`${API_BASE_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
        }

        const result = await response.json();
        localStorage.setItem('accessToken', result.accessToken); // Store token
        localStorage.setItem('userRole', result.role); // Store user role
        accessToken = result.accessToken; // Update global variable
        userRole = result.role; // Update global variable
        alert('Logged in as Municipal User!');
        hideAllForms(); // Hide login form
        updateAuthUI(); // Update UI buttons
        fetchWasteReports(); // Re-fetch reports (e.g., to see full details or ability to clean)
    } catch (error) {
        console.error('Login failed:', error);
        alert('Login failed: ' + error.message);
    }
});

// Handles marking a report as cleaned by a municipal user
cleanReportForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const reportId = cleanReportIdInput.value; // Get report ID from hidden input
    const cleanedImage = cleanedImageInput.files[0]; // Get the uploaded cleaned image

    if (!cleanedImage) {
        alert('Please upload a photo of the cleaned area.');
        return;
    }
    if (!accessToken) {
        alert('You must be logged in to mark a report as cleaned.');
        return;
    }

    const formData = new FormData();
    formData.append('cleanedImage', cleanedImage); // 'cleanedImage' matches multer field name

    try {
        const response = await fetch(`${API_BASE_URL}/clean-report/${reportId}`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${accessToken}` // Send JWT for authentication
            },
            body: formData,
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
        }

        const result = await response.json();
        alert('Area marked as cleaned successfully!');
        console.log('Clean success:', result);
        hideAllForms(); // Close the details popup
        fetchWasteReports(); // Refresh markers on map (the cleaned spot should disappear)
    } catch (error) {
        console.error('Error marking report as cleaned:', error);
        alert('Failed to mark report as cleaned: ' + error.message);
    }
});

// --- Leaderboard Functions ---

// Fetches leaderboard data from the backend
async function fetchLeaderboard() {
    try {
        const response = await fetch(`${API_BASE_URL}/leaderboard`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const leaderboardData = await response.json();
        renderLeaderboard(leaderboardData); // Display the leaderboard
    } catch (error) {
        console.error('Error fetching leaderboard:', error);
        alert('Could not load leaderboard.');
    }
}

// Renders the leaderboard data into the HTML table
function renderLeaderboard(data) {
    leaderboardTableBody.innerHTML = ''; // Clear existing rows
    if (data.length === 0) {
        leaderboardTableBody.innerHTML = '<tr><td colspan="3">No reports yet to form a leaderboard.</td></tr>';
        return;
    }

    data.forEach((entry, index) => {
        const row = leaderboardTableBody.insertRow(); // Create a new table row
        row.insertCell(0).textContent = index + 1; // Rank (1-based index)
        row.insertCell(1).textContent = entry.reported_by || 'Anonymous'; // Reporter name
        row.insertCell(2).textContent = entry.total_points; // Total points
    });
    showElement(leaderboardContainer); // Show the leaderboard container
}


// --- Event Listeners (Connect buttons to functions) ---

// Show Report Waste Form button
showReportFormBtn.addEventListener('click', () => {
    hideAllForms(); // Hide others
    wasteReportForm.reset(); // Clear form inputs
    capturedFile = null; // Reset captured file state
    hideElement(capturedImagePreview); // Hide image preview
    // Pre-fill latitude/longitude if user's location is known
    latitudeInput.value = userLocation ? userLocation.lat.toFixed(6) : '';
    longitudeInput.value = userLocation ? userLocation.lng.toFixed(6) : '';
    showElement(reportFormContainer); // Show the report form
    startCamera(); // Automatically try to start camera
});

// Show Leaderboard button
showLeaderboardBtn.addEventListener('click', () => {
    hideAllForms();
    fetchLeaderboard(); // Fetch and display leaderboard
});

// Show Municipal Login button
showMunicipalLoginBtn.addEventListener('click', () => {
    hideAllForms();
    municipalLoginForm.reset(); // Clear login form inputs
    showElement(municipalLoginFormContainer); // Show login form
});

// Logout button
logoutBtn.addEventListener('click', () => {
    localStorage.removeItem('accessToken'); // Remove token
    localStorage.removeItem('userRole'); // Remove role
    accessToken = null; // Clear global variables
    userRole = null;
    alert('Logged out successfully.');
    updateAuthUI(); // Update UI
    hideAllForms(); // Hide any open municipal forms
    fetchWasteReports(); // Re-fetch reports (to hide municipal controls on details)
});

// --- Initial Setup on Page Load ---
// This runs when the entire HTML document has been loaded and parsed.
document.addEventListener('DOMContentLoaded', () => {
    initializeMap(); // Setup the map
    updateAuthUI(); // Set initial visibility of login/logout buttons
});