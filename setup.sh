#!/bin/bash

# Install dependencies
npm install

# Create a favicon placeholder
echo "Creating favicon placeholder..."
echo '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 32 32">
  <rect width="32" height="32" fill="#3366cc"/>
  <text x="16" y="22" text-anchor="middle" fill="white" font-family="Arial" font-weight="bold" font-size="20">S</text>
</svg>' > public/favicon.svg

echo "Setup complete! Run 'npm run dev' to start the development server."