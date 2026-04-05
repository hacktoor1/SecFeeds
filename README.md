# Security Writeups Fetcher

A powerful plugin to stay updated with the latest in cybersecurity. Fetch full-content security writeups from various popular security platforms and custom RSS sources directly.

## Features

- **Multiple Sources:** Fetch full-content writeups from platforms like:
  - `pentester.land`
  - `infosecwriteups.com`
  - `bugbountyhunting.com`
- **Custom RSS Support:** Add custom RSS feeds to track specific writeup sources.
- **Preview:** Preview writeups and content before saving them.
- **Advanced Filtering:** Filter fetched items by tags or date to easily find relevant content.
- **Reliable Fetching:** Automatically retry failed items to ensure you don't miss important writeups.

## Installation

### Manual Installation 
1. Download the latest release from the repository.
2. Extract the `Security Writeups Fetcher` folder.
3. Move the folder into your plugin directory (e.g., your Obsidian vaults' `.obsidian/plugins/` folder).
4. Reload the plugins in your app and enable **Security Writeups Fetcher**.

## Structure

- `main.js`: Core logic for fetching, filtering, and plugin initialization.
- `styles.css`: Styles for the UI elements like the preview modal and input fields.
- `data.json`: Local storage for plugin settings and cached feed data.
- `manifest.json`: Plugin metadata and configuration properties.
