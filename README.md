# AQI monitoring for pollution Control : AQI Visualization Using Google Maps

## Overview
This project fetches Air Quality Index (AQI) data for given locations, stores it in a database, and visualizes it on Google Maps with color-coded markers based on AQI levels.

## Features
- **File Upload System**: Accepts `.txt` or `.data` files containing location names.
- **Geolocation Extraction**: Retrieves latitude and longitude for given locations.
- **AQI Data Retrieval**: Fetches real-time AQI data using Google's Air Quality API.
- **Database Storage**: Stores location data and AQI values in SQLite.
- **Google Maps Integration**: Displays AQI data on an interactive map with markers.
- **Web Application**: User-friendly interface for uploading files and viewing AQI levels.

## Technologies Used
- **Backend**: Python, Flask
- **Frontend**: HTML, CSS, JavaScript (Google Maps API)
- **Database**: SQLite
- **APIs**: Google Maps Geocoding & Air Quality API

## Installation

### Prerequisites
- Python 3.8+
- Virtual environment (`venv` or `conda`)
- Google Maps API key with Air Quality access

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/tejask0512/AQI-Google-Maps.git
   cd AQI-Google-Maps
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up API keys in `config.py`:
   ```python
   API_KEY = "your_google_maps_api_key"
   ```

5. Run the application:
   ```bash
   python app.py
   ```

## Usage
- Access the web application at `http://localhost:5000`
- Upload a `.txt` or `.data` file containing locations
- View AQI data visualized on Google Maps with markers
- Hover over markers to see AQI details

## Roadmap
- Implement multi-location AQI comparison
- Improve UI with advanced filtering options
- Deploy to cloud for public access

## Contribution
Contributions are welcome! Fork the repo and submit a PR.

## License
This project is licensed under the MIT License.

## Contact
- **Author**: Tejas Kamble
- **Website**: [tejaskamble.com](https://tejaskamble.com)
- **GitHub**: [tejask0512](https://github.com/tejask0512)
