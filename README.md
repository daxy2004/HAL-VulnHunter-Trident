# VulnHunter – A Web Security Arsenal


The **Security Scanner** is a full-stack application designed to perform security scans on websites, identify vulnerabilities, and visualize the results in a user-friendly interface. The backend is built using **Python** and **FastAPI**, while the frontend is a **React** application. Users can view scan results, explore vulnerabilities, and download detailed PDF reports.

---

## Features

### Frontend (React)
- **Scan Results Visualization**:
  - View detailed information about vulnerabilities, including severity, location, and recommendations.
  - Expandable vulnerability details with descriptions and proof of concept (if available).
  - List of discovered subdomains with their status, IP address, and server information.

- **PDF Report Generation**:
  - Generate and download a professional PDF report containing:
    - Scan overview (scanned URL, pages scanned, forms found).
    - Identified vulnerabilities with recommendations.
    - Discovered subdomains with their details.

- **Real-Time Status Updates**:
  - Displays the scan status (pending, completed, failed) with appropriate feedback.
  - Automatically updates the results when the scan is completed.

- **Responsive UI**:
  - Built using Material-UI for a clean and responsive design.

### Backend (FastAPI)
- **RESTful API**:
  - Provides endpoints to fetch scan results and status.
  - Handles scan requests and processes data for the frontend.

- **Security Scanning Logic**:
  - Performs security scans on the target website.
  - Identifies vulnerabilities (e.g., XSS, SQL Injection) and subdomains.

---

## Technologies Used

### Frontend
- **React**
- **Material-UI (MUI)** for UI components
- **jsPDF** and **jspdf-autotable** for PDF generation

### Backend
- **Python**
- **FastAPI** for building the REST API
- (Optional) Libraries for security scanning (e.g., `requests`, `beautifulsoup4`, `sqlmap`, etc.)

---

## Installation

### Prerequisites

- **Frontend**:
  - Node.js (v16 or higher)
  - npm (v8 or higher)

- **Backend**:
  - Python (v3.8 or higher)
  - pip (Python package manager)

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/security-scanner.git
   cd security-scanner
   ```

2. **Backend Setup**:
   - Navigate to the backend directory:
     ```bash
     cd backend
     ```
   - Create a virtual environment:
     ```bash
     python -m venv venv
     ```
   - Activate the virtual environment:
     - On Windows:
       ```bash
       venv\Scripts\activate
       ```
     - On macOS/Linux:
       ```bash
       source venv/bin/activate
       ```
   - Install dependencies:
     ```bash
     pip install -r requirements.txt
     ```
   - Start the FastAPI server:
     ```bash
     uvicorn main:app --reload
     ```
   - The backend will be available at `http://localhost:8000`.

3. **Frontend Setup**:
   - Navigate to the frontend directory:
     ```bash
     cd ../frontend
     ```
   - Install dependencies:
     ```bash
     npm install
     ```
   - Start the development server:
     ```bash
     npm start
     ```
   - The frontend will be available at `http://localhost:3000`.

---

## Usage

### Running the Application

1. Start the **backend** server (FastAPI):
   ```bash
   cd backend
   uvicorn main:app --reload
   ```

2. Start the **frontend** development server:
   ```bash
   cd ../frontend
   npm start
   ```

3. Open your browser and navigate to `http://localhost:3000`.

### Viewing Scan Results

1. Enter the `scanId` in the application (if applicable).
2. The application will fetch and display the scan results in real-time.
3. Use the interface to:
   - View vulnerabilities and their details.
   - Explore discovered subdomains.
   - Download a PDF report of the scan results.

### Generating a PDF Report

1. Click the **Download Full Report** button.
2. A PDF file (`security_report_<scanId>.pdf`) will be generated and downloaded automatically.

---

## API Endpoints

The backend provides the following RESTful API endpoints:

### Fetch Scan Results
- **Endpoint**: `GET /api/scan/{scanId}`
- **Response**:
  ```json
  {
    "status": "completed",
    "results": {
      "base_url": "https://example.com",
      "pages_scanned": 10,
      "forms_found": 5,
      "vulnerabilities": [
        {
          "vulnerability_type": "XSS",
          "severity": "High",
          "url": "https://example.com/login",
          "description": "Cross-site scripting vulnerability found in the login form.",
          "recommendation": "Implement input validation. Use CSP headers.",
          "proof_of_concept": "Payload: <script>alert('XSS')</script>"
        }
      ],
      "subdomains": [
        {
          "subdomain": "sub.example.com",
          "status": "Live",
          "ip_address": "192.168.1.1",
          "server": "nginx"
        }
      ]
    }
  }
  ```

---

## Folder Structure

```
security-scanner/
├── backend/
│   ├── main.py                  # FastAPI application
│   ├── requirements.txt         # Python dependencies
│   └── venv/                    # Virtual environment (ignored in .gitignore)
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── components/
│   │   │   └── ResultsView.jsx  # Main component for scan results
│   │   ├── App.js
│   │   ├── index.js
│   │   └── styles/
│   ├── package.json
│   └── README.md
├── README.md
└── .gitignore
```

---

## Dependencies

### Backend
- **FastAPI**: Web framework for building APIs.
- **Uvicorn**: ASGI server for running FastAPI.
- **Other Python libraries**: For security scanning logic.

Install backend dependencies:
```bash
pip install -r backend/requirements.txt
```

### Frontend
- **React**: JavaScript library for building the user interface.
- **Material-UI (MUI)**: UI component library for React.
- **jsPDF**: Library for generating PDF files.
- **jspdf-autotable**: Plugin for creating tables in PDFs.

Install frontend dependencies:
```bash
cd frontend
npm install
```

---

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/YourFeatureName`).
3. Commit your changes (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature/YourFeatureName`).
5. Open a pull request.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

