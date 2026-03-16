#!/usr/bin/env node

/**
 * Generate index.json for writeups repository
 * Fetches all markdown files and their commit history to determine creation and modification dates
 */

const https = require('https');
const fs = require('fs');
const path = require('path');

const REPO_OWNER = process.env.REPO_OWNER || 'timothy0509';
const REPO_NAME = process.env.REPO_NAME || 'writeups';
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;

const API_BASE = 'api.github.com';

const NICKNAME_MAP = {
  'timothy0509': 'Timothy',
  'DXinschool': 'DXuwu',
  'SYJCsteve': 'steve'
};

function getNickname(username) {
  return NICKNAME_MAP[username] || username;
}

/**
 * Make an authenticated HTTPS request to GitHub API
 */
function makeRequest(options) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: API_BASE,
      path: options.path,
      method: options.method || 'GET',
      headers: {
        'User-Agent': 'Writeups-Index-Generator',
        'Accept': 'application/vnd.github.v3+json',
        ...(GITHUB_TOKEN && { 'Authorization': `token ${GITHUB_TOKEN}` }),
        ...options.headers
      }
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve({ data: parsed, headers: res.headers, statusCode: res.statusCode });
          } else {
            reject(new Error(`API Error ${res.statusCode}: ${parsed.message || data}`));
          }
        } catch (e) {
          reject(new Error(`Failed to parse response: ${e.message}`));
        }
      });
    });

    req.on('error', reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

/**
 * Fetch all files from the repository using Git Trees API
 */
async function fetchAllFiles() {
  console.log('Fetching repository tree...');
  const { data } = await makeRequest({
    path: `/repos/${REPO_OWNER}/${REPO_NAME}/git/trees/main?recursive=1`
  });

  // Filter only markdown files (blobs only, not submodules or symlinks)
  const mdFiles = data.tree
    .filter(item => item.type === 'blob' && item.path.endsWith('.md'))
    .map(item => item.path);

  console.log(`Found ${mdFiles.length} markdown files`);
  return mdFiles;
}

/**
 * Parse Link header to get total count and last page
 */
function parseLinkHeader(linkHeader) {
  if (!linkHeader) return { total: 0, lastPage: 0 };

  const lastMatch = linkHeader.match(/page=(\d+)[^>]*>;\s*rel="last"/);
  if (lastMatch) {
    const lastPage = parseInt(lastMatch[1], 10);
    return { total: lastPage, lastPage };
  }

  // If no last link, try to find from page numbers
  const pageMatches = linkHeader.match(/page=(\d+)/g);
  if (pageMatches) {
    const pages = pageMatches.map(p => parseInt(p.replace('page=', ''), 10));
    const lastPage = Math.max(...pages);
    return { total: lastPage, lastPage };
  }

  return { total: 0, lastPage: 0 };
}

/**
 * Fetch commit dates for a specific file
 */
async function fetchFileCommits(filePath) {
  try {
    // Fetch first page (most recent commit)
    const firstPageResponse = await makeRequest({
      path: `/repos/${REPO_OWNER}/${REPO_NAME}/commits?path=${encodeURIComponent(filePath)}&per_page=1&page=1`
    });

    let lastModified = null;
    let writer = null;
    if (firstPageResponse.data && firstPageResponse.data.length > 0) {
      lastModified = firstPageResponse.data[0].commit.committer.date;
      writer = firstPageResponse.data[0].author?.login || null;
    }

    // Get total pages from Link header
    const linkHeader = firstPageResponse.headers.link;
    const { lastPage } = parseLinkHeader(linkHeader);

    let createdAt = lastModified;

    // If there are more pages, fetch the last page for the first commit
    if (lastPage > 1) {
      const lastPageResponse = await makeRequest({
        path: `/repos/${REPO_OWNER}/${REPO_NAME}/commits?path=${encodeURIComponent(filePath)}&per_page=1&page=${lastPage}`
      });

      if (lastPageResponse.data && lastPageResponse.data.length > 0) {
        createdAt = lastPageResponse.data[0].commit.committer.date;
      }
    }

    return {
      createdAt,
      lastModified: lastModified || createdAt,
      writer
    };
  } catch (error) {
    console.warn(`Warning: Failed to fetch commits for ${filePath}: ${error.message}`);
    return {
      createdAt: null,
      lastModified: null,
      writer: null
    };
  }
}

/**
 * Extract slug components from file path
 */
function parsePath(filePath) {
  const parts = filePath.replace(/\.md$/, '').split('/');
  const event = parts[0] || '';
  const category = parts[1] || '';
  const title = parts[parts.length - 1] || '';

  return {
    slug: parts,
    event,
    category,
    title,
    path: filePath
  };
}

/**
 * Main function
 */
async function main() {
  try {
    console.log('Starting index generation...');
    console.log(`Repository: ${REPO_OWNER}/${REPO_NAME}`);

    // Fetch all markdown files
    const files = await fetchAllFiles();

    if (files.length === 0) {
      console.log('No markdown files found. Generating empty index.');
      const emptyIndex = {
        generatedAt: new Date().toISOString(),
        writeups: []
      };
      fs.writeFileSync('index.json', JSON.stringify(emptyIndex, null, 2));
      console.log('Empty index.json generated successfully.');
      return;
    }

    // Process each file
    const writeups = [];
    for (let i = 0; i < files.length; i++) {
      const filePath = files[i];
      console.log(`[${i + 1}/${files.length}] Processing: ${filePath}`);

      const { slug, event, category, title } = parsePath(filePath);
      const { createdAt, lastModified, writer } = await fetchFileCommits(filePath);
      const nickname = getNickname(writer);

      writeups.push({
        slug,
        event,
        category,
        title,
        path: filePath,
        createdAt,
        lastModified,
        writer,
        nickname
      });
    }

    // Sort writeups by lastModified (newest first), then by createdAt
    writeups.sort((a, b) => {
      const dateA = new Date(a.lastModified || 0);
      const dateB = new Date(b.lastModified || 0);
      return dateB - dateA;
    });

    // Generate index
    const index = {
      generatedAt: new Date().toISOString(),
      writeups
    };

    // Write index.json
    fs.writeFileSync('index.json', JSON.stringify(index, null, 2));
    console.log('\n✅ Index generated successfully!');
    console.log(`   Total writeups: ${writeups.length}`);
    console.log(`   Generated at: ${index.generatedAt}`);

    // Summary statistics
    const withDates = writeups.filter(w => w.createdAt).length;
    const withoutDates = writeups.length - withDates;
    console.log(`   Files with dates: ${withDates}`);
    if (withoutDates > 0) {
      console.log(`   Files without dates: ${withoutDates}`);
    }

  } catch (error) {
    console.error('\n❌ Error generating index:', error.message);
    process.exit(1);
  }
}

// Run the generator
main();
