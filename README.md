# MAESTRO Threat Analyzer

> **Official Repository**: This is the official Cloud Security Alliance repository for the MAESTRO Threat Analyzer.

The MAESTRO Threat Analyzer is an AI-powered tool designed to help developers and security professionals identify and mitigate potential threats in multi-agent systems. It uses large language models via Genkit—including Google Gemini, OpenAI, and locally hosted Ollama models—together with the MAESTRO threat modeling framework to analyze system architectures and generate detailed security insights.

This tool is built for educational and demonstrative purposes to showcase how threat modeling can be applied to complex, agentic AI systems.

## Reference

This tool is based on the **MAESTRO** framework for agentic AI threat modeling, as detailed in the Cloud Security Alliance (CSA) publication:

- **Paper**: [Agentic AI Threat Modeling Framework: MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro)

We highly recommend reading the paper to understand the seven-layer architecture and the principles behind this tool.

## Features

- **Automatic Codebase Discovery**: Choose a local repository folder once. The configured model selects relevant files from a filtered repository map, follows references in a second pass, and extracts an editable architecture description with file/line evidence and explicit unknowns. Manual file selection remains available.

- **Detailed Architecture Input**: Provides a textarea for users to describe their system architecture, which is used by the AI for analysis.
- **Use-Case Presets**: Comes with pre-populated use-case descriptions that detail interactions between agents using protocols like **A2A (Agent-to-Agent)** and **MCP (Model Context Protocol)**.
- **AI-Powered Threat Identification**: For each of the seven MAESTRO layers, the tool uses a Genkit flow to call the configured LLM provider. The AI identifies two categories of threats:
  - **Traditional Threats**: Inherent security risks for the layer's technology, independent of agentic factors.
  - **Agentic Threats**: Novel threats or exacerbations of existing ones arising from factors like Non-Determinism, Autonomy, and No Trust Boundary.
- **AI-Driven Mitigation Generation**: For each identified threat, the AI recommends specific mitigation strategies, including the reasoning behind them and any potential caveats.
- **Real-Time Analysis & Logging**: The UI streams the analysis progress in real-time, providing detailed logs as the AI works through each of the seven MAESTRO layers.

## Getting Started

Follow these instructions to set up and run the project locally.

### Prerequisites

- Node.js (v18 or later)
- npm or yarn

### Installation & Setup

1. **Clone the repository:**

   ```bash
   git clone https://github.com/CloudSecurityAlliance/MAESTRO.git
   cd MAESTRO
   ```

2. **Install dependencies:**

   ```bash
   npm install
   ```

3. **Set up environment variables:**
   - Create a `.env` file in the root of the project.
   - Choose which provider to use by setting `LLM_PROVIDER` to `google`, `openai`, or `ollama` (defaults to `google`).
   - Provide the appropriate credentials for the selected provider:

     ```markdown
     # For Google Gemini
     GEMINI_API_KEY=your_api_key_here

     # For OpenAI
     OPENAI_API_KEY=your_api_key_here
        
     # For Ollama
     OLLAMA_SERVER_ADDRESS=http://localhost:11434

     # Optional: override the default model
     LLM_MODEL=model-name
     ```

### Running the Application

This project requires two processes to run concurrently: the Next.js frontend and the Genkit AI flows.

1. **Run the Next.js development server:**
   Open a terminal and run:

   ```bash
   npm run dev
   ```

   This will start the web application, typically available at `http://localhost:9002`.

2. **Run the Genkit flows:**
   Open a second terminal and run:

   ```bash
   npm run genkit:watch
   ```

   This command starts the Genkit development server and automatically reloads it when you make changes to your AI flows.

You can now open your browser and start using the MAESTRO Threat Analyzer.

## Analyze a codebase

1. In the sidebar, use **Start from source code** to choose the repository folder. The browser builds a map of relative paths and sizes without reading file contents or sending anything. **Automatic** file selection is the default. Individual files can also be supplied.
2. Optionally expand **Review or exclude files** to preview source locally and exclude sensitive or irrelevant files before discovery. Common credential files, environment files, dependency directories, build output and lockfiles are excluded by conservative filename rules. These rules are not a complete secret detector or a `.gitignore` parser. Remove embedded secrets before extraction.
3. Click **Extract Architecture**. The application sends the eligible file map to the configured model, which selects an initial set of source files. The browser reads only those validated paths. A follow-up model call examines that source and can request additional eligible files by following imports, configuration references and service/tool registrations. Finally, the extraction flow analyzes the combined selection. No file-by-file selection is required from the user.
4. Review the read-file list, selection reasoning and populated **Architecture Description**, including source references, map coverage and unknowns. References are checked against supplied paths and line ranges; a person must verify that each cited passage supports the model's interpretation.
5. Click **Generate Analysis** to run the existing threat, mitigation and executive-summary workflow. The seven-layer analysis uses the extracted description and evidence, not a second pass over all raw files. Regenerate the optional diagram for the new architecture before exporting a report.

**Discovery limits:** the map includes at most **2,000 eligible paths** and **192 KiB of metadata**. When the map overflows, manifests and entry points receive priority, followed by architecture-related paths. Exclusions and overflow reasons appear in the UI. Oversized source files are excluded before mapping. Binary or unsupported text content is rejected when read.

Automatic discovery uses at most **two selection calls** followed by **one extraction call**. The initial source selection is limited to **30 files / 80 KiB**, leaving room for a follow-up. Combined source limits are **60 files**, **32 KiB per file**, and **160 KiB total**. Both server and browser validate model-selected paths and budgets. The model cannot read arbitrary local paths, request URLs or execute code. An invalid selection stops the workflow rather than falling back to uploading the whole repository.

To choose files yourself, switch **File selection** to **Manual selection**. Checked files are read in path order within the same source limits, and only the extraction call is used. For larger repositories, choose a smaller subsystem for additional coverage. Files are not silently truncated. ZIP/Git URL ingestion, combining multiple extractions, and exhaustive large-repository analysis are not supported.

**Data handling:** after **Extract Architecture** is clicked, the file map and requested source pass through the Next.js server to the configured `LLM_PROVIDER`/`LLM_MODEL`. A cloud provider receives that data; Ollama receives it at the configured server address. Provider policies and any enabled Genkit tracing also apply. The follow-up pass can select additional eligible files automatically under the same action.

This is selective model-assisted source review and architecture extraction, not a claim that every file or line has been inspected. A path appearing in the repository map does not mean its contents were reviewed. It is not a compiler-based static analyzer, dependency vulnerability scan, penetration test or verification of runtime controls. The normal text/preset input remains available. Extracted descriptions and selected content remain in the current browser session; the application does not add repository storage.

### Development checks

Use a Node.js version compatible with the locked dependencies (for example Node 22.12 or later). Run `npm ci`, `npm run test:run`, `npm run typecheck`, and `npm run build`. Codebase tests cover metadata-only indexing, selection budgets, follow-up discovery, rejected model paths, filtering, byte limits, evidence references, server validation, manual selection and the automatic UI handoff without calling a live model.

## How to Contribute

We welcome contributions! If you'd like to help improve the tool, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them with clear, descriptive messages.
4. Push your branch and open a pull request.

Please ensure your code follows the existing style and that you've tested your changes.

## Disclaimer

This tool is intended for **educational and demonstration purposes only**. The threat analysis and mitigation strategies are generated by an AI model based on the MAESTRO methodology.

**AI can make mistakes.** The information provided by this tool should not be considered a complete or authoritative security audit. Always perform a thorough, manual review and consult with security professionals before implementing any recommended mitigations. The creators of this tool are not responsible for any security vulnerabilities or issues that may arise from its use.

## License

This project is licensed under the MIT License.

```txt
MIT License

Copyright (c) 2024 Distributed Apps

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Contact

For questions, feedback, or inquiries, please contact us at **[info@distributedapps.ai](mailto:info@distributedapps.ai)**.
