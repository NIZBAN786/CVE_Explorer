---
title: CVE_Explorer
app_file: app.py
sdk: gradio
sdk_version: 5.9.1
---
# CVE_Explorer

**CVE_Explorer** is a powerful tool designed to fetch and display detailed information about Common Vulnerabilities and Exposures (CVEs) from multiple trusted sources, such as the National Vulnerability Database (NVD) and the CNA API. It allows users to interact with the CVE data, browse random CVEs, and save CVE details to CSV files for offline use.

## Features

- **Fetch CVE Details**: Retrieve comprehensive details about CVEs from the NVD and CNA API.
- **Random CVEs**: View random CVEs to explore various vulnerabilities.
- **CSV Export**: Save CVE details to a CSV file for easy reference and sharing.
- **User-Friendly Interface**: Built with Gradio to offer an intuitive and easy-to-use web interface.
- **Multi-Source Support**: Integrates data from NVD and CNA to provide diverse perspectives on CVE information.

## Installation

Follow these steps to set up CVE_Explorer on your local machine:

### 1. Clone the Repository

```bash
git clone https://github.com/NIZBAN786/CVE_Explorer.git
cd CVE_Explorer
```

### 2. Install the Required Dependencies

Ensure you have Python 3.x installed, then install the necessary dependencies:

```bash
pip install -r requirements.txt
```

### 3. Verify Installation

Ensure everything is set up correctly by checking the installed packages:

```bash
pip list
```

You should see the list of packages, including Gradio and any other dependencies mentioned in `requirements.txt`.

## Usage

### 1. Run the Application

Start the application with the following command:

```bash
python app.py
```

### 2. Access the Gradio Interface

Once the application starts, open the provided local server URL (typically `http://localhost:7860`) in your browser to interact with the web interface.

### 3. Fetch CVE Details

- Enter a CVE ID (e.g., `CVE-2024-32881`) into the input field to fetch detailed information about a specific vulnerability from the NVD and CNA API.
  
### 4. View Random CVEs

Click the **"Refresh"** button to display random CVEs, giving you an opportunity to explore various vulnerabilities.

### 5. Export to CSV

- Use the "Save to CSV" button to export the displayed CVE details to a CSV file for offline use.

## Project Structure

The repository contains the following key files:

- **[app.py](app.py)**: Main application file containing the logic for fetching and displaying CVE details.
- **[requirements.txt](requirements.txt)**: Lists all dependencies required for the project.
- **[README.md](README.md)**: This file, which provides an overview of the project and setup instructions.
  
## Contributing

We welcome contributions! If you would like to improve this tool, feel free to submit a Pull Request. When contributing, please adhere to the following guidelines:

- **Fork** the repository.
- Create a **new branch** for your changes.
- **Commit** your changes with clear and concise messages.
- **Open a pull request** to the `main` branch.

## License

This project is licensed under the [MIT License](LICENSE), which allows for personal, academic, or commercial use.

## Author

- **GitHub**: [NIZBAN786](https://github.com/NIZBAN786)

---
