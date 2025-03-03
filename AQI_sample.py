import requests
import json

API_KEY = "your_api_key"

def get_air_quality(lat, lng):
    url = f"https://airquality.googleapis.com/v1/currentConditions:lookup?key={API_KEY}"
    headers = {"Content-Type": "application/json"}
    payload = {"location": {"latitude": lat, "longitude": lng}}

    response = requests.post(url, json=payload, headers=headers)

    # Debugging: Print raw response
    print("Response Status Code:", response.status_code)
    print("Raw Response:", response.text)

    if response.status_code == 200:
        try:
            data = response.json()
            print("Parsed JSON:", json.dumps(data, indent=4))  # Pretty print JSON for debugging
            
            # Check if 'currentConditions' key exists
            if 'currentConditions' in data:
                return data['currentConditions']
            else:
                return {"error": "Missing 'currentConditions' key in API response."}
        except json.JSONDecodeError:
            return {"error": "Failed to decode JSON response."}
    else:
        return {"error": f"Request failed with status code {response.status_code}", "details": response.text}

# Example usage
lat, lng = 37.7749, -122.4194  # Example coordinates (San Francisco)
air_quality_data = get_air_quality(lat, lng)
print("Final Processed Data:", air_quality_data)
