# AQI-Google Maps Integration

## Project Overview
This project integrates real-time Air Quality Index (AQI) data with Google Maps, providing users with a visual representation of air quality across different locations. The application displays color-coded markers on a map interface, allowing users to quickly assess air quality conditions in various regions.

## Features
- Interactive Google Maps interface for visualizing AQI data
- Color-coded markers representing different air quality levels
- Real-time AQI data retrieval from monitoring stations
- Detailed information display when clicking on map markers
- Responsive design for various device sizes

## Technology Stack
- Frontend: HTML, CSS, JavaScript
- Maps: Google Maps JavaScript API
- AQI Data: Air Quality Open Data Platform API
- Hosting: GitHub Pages

## Project Structure
```
AQI-Google-Maps/
│
├── css/                       # Styling files
│   └── style.css              # Main CSS file for the application
│
├── js/                        # JavaScript files
│   ├── aqi_data.js            # Handles AQI data fetching and processing
│   ├── map_configuration.js   # Configures Google Maps settings
│   └── markers.js             # Manages map markers and info windows
│
├── images/                    # Image assets for the project
│   └── aqi_legend.png         # Legend showing AQI color codes
│
├── index.html                 # Main HTML file - entry point for the application
├── README.md                  # Project documentation
└── LICENSE                    # License information
```

## Setup and Installation

### Prerequisites
- Google Maps JavaScript API key
- Modern web browser
- Internet connection

### Local Development
1. Clone the repository:
```bash
git clone https://github.com/tejask0512/AQI-Google-Maps.git
cd AQI-Google-Maps
```

2. Replace the Google Maps API key placeholder in `index.html` with your actual API key:
```html
<script src="https://maps.googleapis.com/maps/api/js?key=YOUR_API_KEY&callback=initMap" async defer></script>
```

3. Open `index.html` in your web browser to view the application.

### Getting a Google Maps API Key
1. Visit the [Google Cloud Platform Console](https://console.cloud.google.com/).
2. Create a new project (or select an existing one).
3. Navigate to APIs & Services > Dashboard and enable the "Maps JavaScript API".
4. Create credentials to get your API key.
5. Make sure to restrict the API key for security purposes.

## How It Works

### AQI Data Retrieval
The application fetches AQI data from an air quality monitoring API. This data includes:
- Location coordinates (latitude and longitude)
- Current AQI values
- Pollutant concentrations
- Timestamp of measurements

### Map Visualization
1. The Google Map loads centered on a default location.
2. AQI data is processed and converted into map markers.
3. Markers are color-coded based on the AQI value:
   - Green: Good (0-50)
   - Yellow: Moderate (51-100)
   - Orange: Unhealthy for Sensitive Groups (101-150)
   - Red: Unhealthy (151-200)
   - Purple: Very Unhealthy (201-300)
   - Maroon: Hazardous (301+)
4. Clicking on a marker displays detailed information about the air quality at that location.

### User Interaction
- Users can navigate the map using standard Google Maps controls (zoom, pan, etc.)
- Clicking on markers reveals AQI details in an info window
- The interface includes a legend explaining the color code system

## Contributing
Contributions to improve the AQI-Google Maps integration are welcome. Please follow these steps:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Future Enhancements
- Add user location detection for immediate local AQI information
- Implement historical AQI data visualization
- Add predictive air quality forecasting
- Create custom filtering options for different pollutants
- Develop mobile application versions

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments
- [Google Maps Platform](https://developers.google.com/maps) for map visualization
- Air Quality Open Data Platform for providing AQI data
- Contributors and maintainers of this project
