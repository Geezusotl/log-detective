# Publish the project on GitHub

The project is published at [Geezusotl/log-detective](https://github.com/Geezusotl/log-detective). The following steps explain how to publish a separate copy. To use the existing project, select **Code → Download ZIP**, extract it, and launch `StartLogDetective.bat`.

## Suggested repository details

- Name: `log-detective`
- Description: `Local log investigation with evidence-linked findings, troubleshooting checklists, report export, and optional AI explanations.`
- Topics: `python`, `troubleshooting`, `log-analysis`, `ollama`, `developer-tools`, `ai`

## Using GitHub's upload page

1. Sign into GitHub and create a public repository named `log-detective`.
2. Leave the initial README, license, and gitignore options empty; this project includes them.
3. Select **uploading an existing file**.
4. Upload the contents of the extracted `LogDetective` folder, keeping the folder structure. The README must be at the repository root, not inside an extra outer folder.
5. Include `.github/workflows/tests.yml` and `.gitignore`. Dot-prefixed files can be hidden by some file pickers, so check that they appear afterward.
6. Use a commit message such as `Add Log Detective local investigation app`.
7. Open the Actions tab to see the project checks. These checks only run after upload and are separate from the checks performed during development.
8. Pin the repository on your profile.

If the upload page makes preserving folders awkward, use GitHub Desktop: add the extracted project as a local repository, commit its files, and select **Publish repository**.

## Keep personal logs out of the repository

Publish only synthetic samples. Do not upload exported reports, personal logs, tokens, or model files. The gitignore excludes common generated artifacts, but it cannot identify all sensitive files for you.

## A simple demo for the README or an interview

Launch the app, choose the Python import sample, analyze it, open L6, mark a check complete, and export the report. This demonstrates the full functional path in about a minute.
