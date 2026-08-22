# Python Vulnerability Scanner - VS Code Setup & API Guide

This guide provides step-by-step instructions for setting up, running, and configuring your Python Vulnerability Scanner project in Visual Studio Code.

---

## Part 1: How to Download and Open in VS Code

1. **Download the Project Archive**: Click the download link provided in the final result message to download `python-vulnerability-scanner.zip`.
2. **Extract the ZIP Archive**: Extract the downloaded ZIP file to a preferred directory on your computer (e.g., your Documents or Projects folder).
3. **Open in VS Code**:
   - Open Visual Studio Code.
   - Click **File > Open Folder...** and select the extracted `python-vulnerability-scanner` folder.
4. **Open the Integrated Terminal**: In VS Code, open the built-in terminal by pressing `` Ctrl + ` `` (or `Cmd + ` ` on macOS) or selecting **Terminal > New Terminal**.

---

## Part 2: Step-by-Step Instructions to Run the Code

### Step 1: Install Prerequisites
Ensure you have the following installed on your machine:
- **Node.js** (v18 or higher recommended): Download from [nodejs.org](https://nodejs.org/).
- **pnpm** (preferred package manager): Install globally via terminal by running:
  ```bash
  npm install -g pnpm
  ```

### Step 2: Install Project Dependencies
In the VS Code terminal (inside the project root directory), run:
```bash
pnpm install
```
This will install all required frontend and backend dependencies, including React, Express, tRPC, Tailwind CSS, and Vite.

### Step 3: Configure Environment Variables
1. In the root of your project folder, create a new file named `.env`.
2. Populate it with your local development configuration. For basic static code scanning and UI testing, you can use:
   ```env
   PORT=3000
   NODE_ENV=development
   DATABASE_URL=mysql://root:root@localhost:3306/vulnerability_scanner
   JWT_SECRET=your-super-secret-jwt-key-change-this
   ```
   *(Note: If you are not using a local MySQL database for persistence, the app runs with in-memory fallbacks for analysis).*

### Step 4: Run the Development Server
Start the full-stack development server by running:
```bash
pnpm dev
```
You will see output indicating that the server is running (typically on `http://localhost:3000`).

### Step 5: Open in Your Browser
Open your web browser and navigate to:
```url
http://localhost:3000
```
You will see the login/landing page. You can sign in and access the fully interactive Python Vulnerability Scanner dashboard.

---

## Part 3: How to Change and Manage API Keys

The application uses built-in secure helpers (`server/_core/llm.ts`) to interact with AI models for vulnerability explanations and remediation recommendations. If you need to update or change your API keys (such as `BUILT_IN_FORGE_API_KEY`, OpenAI API keys, or custom provider keys), follow these steps:

### Method A: Via Environment Variables (`.env`)
1. Open your `.env` file in VS Code.
2. Add or update your API key variable:
   ```env
   BUILT_IN_FORGE_API_KEY=your_new_api_key_here
   BUILT_IN_FORGE_API_URL=https://api.manus.im/v1
   ```
3. If you want to use a direct LLM provider key (e.g., OpenAI or Anthropic), you can configure standard provider environment variables in your `.env` file and update `server/_core/llm.ts` to read them.

### Method B: Via Server Configuration (`server/_core/env.ts`)
1. Open `server/_core/env.ts` in VS Code.
2. Locate where environment variables are loaded and validated using Zod:
   ```ts
   export const ENV = {
     forgeApiKey: process.env.BUILT_IN_FORGE_API_KEY,
     forgeApiUrl: process.env.BUILT_IN_FORGE_API_URL,
     // Add your custom keys here
   };
   ```
3. Restart your dev server (`Ctrl + C` then `pnpm dev`) for changes to take effect.

---

## Part 4: Running Tests

To run the comprehensive test suite (including static analysis rule tests for SQL injection, command injection, hardcoded secrets, dangerous functions, and XSS patterns):
```bash
pnpm test
```
