# Security Scanner - Frontend

The **Security Scanner Frontend** is a React-based application designed to visualize and interact with the results of security scans. It provides a user-friendly interface to view vulnerabilities, subdomains, and other scan-related data. Users can also generate and download detailed PDF reports of the scan results.

---

## Features

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

---

## Technologies Used

- **Frontend**:
  - React
  - Material-UI (MUI) for UI components
  - jsPDF and jspdf-autotable for PDF generation

- **Backend**:
  - (Assumed) A REST API providing scan results in JSON format.

---

## Installation

### Prerequisites

- Node.js (v16 or higher)
- npm (v8 or higher)

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/security-scanner-frontend.git
   cd security-scanner-frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the development server:
   ```bash
   npm start
   ```

4. Open your browser and navigate to `http://localhost:3000`.

---

## Usage

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

## API Integration

The frontend fetches scan results from a backend API. Ensure the backend provides the following data structure:

### Example API Response

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

### API Endpoint

Update the API endpoint in the `ResultsView` component to match your backend:

```javascript
const response = await fetch(`http://localhost:8000/api/scan/${scanId}`);
```

---

## Folder Structure

```
security-scanner-frontend/
├── public/
├── src/
│   ├── components/
│   │   └── ResultsView.jsx
│   ├── App.js
│   ├── index.js
│   └── styles/
├── package.json
├── README.md
└── .gitignore
```

---

## Dependencies

- **React**: JavaScript library for building the user interface.
- **Material-UI (MUI)**: UI component library for React.
- **jsPDF**: Library for generating PDF files.
- **jspdf-autotable**: Plugin for creating tables in PDFs.

Install all dependencies using:
```bash
npm install @mui/material @mui/icons-material jspdf jspdf-autotable
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

---

## Acknowledgments

- Material-UI for providing a robust UI component library.
- jsPDF for simplifying PDF generation in JavaScript.

---
