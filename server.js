const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 4200;

app.use(cors());
app.use(express.json());

const API_KEYS = [
  'e0395c3d4b2f5af317edb585ca2a7960',
  '378ef0b30a694620f4ce15cee45eac92',
  'e664919936b131db4a3b206ad64959d0'
];

const API_SECRETS = [
  '8acb408ad1031078e625f5327824621b',
  '83f4b98aa5d9655de80300273fdf949c',
  'e0596e57cf4226c6a7e57ae0d219a821'
];

const FIREBASE_DB_URL = 'https://scrobblespam-killswitch-default-rtdb.firebaseio.com';
const CALLBACK_URL = 'https://scrobblingoblin.onrender.com/callback';

function md5(str) {
  return crypto.createHash('md5').update(str).digest('hex');
}

async function callLastFmApi(params, secret) {
  const keys = Object.keys(params).sort();
  const sigString = keys.map(k => k + params[k]).join('') + secret;
  const api_sig = md5(sigString);

  const url = new URL('https://ws.audioscrobbler.com/2.0/');
  for (const [k, v] of Object.entries({ ...params, api_sig, format: 'json' })) {
    url.searchParams.append(k, v);
  }

  const res = await fetch(url.toString(), { method: 'POST' });
  return res.json();
}

async function getSessionKeys(discordKey) {
  const url = `${FIREBASE_DB_URL}/accounts/${encodeURIComponent(discordKey)}.json`;
  const res = await fetch(url);
  if (!res.ok) return null;
  const data = await res.json();
  if (!data || !Array.isArray(data.session_keys)) return null;
  return data.session_keys;
}

async function updateSessionKeys(discordKey, sessionKeys) {
  const url = `${FIREBASE_DB_URL}/accounts/${encodeURIComponent(discordKey)}.json`;
  const res = await fetch(url, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_keys: sessionKeys }),
  });
  return res.ok;
}

async function logError(discordKey, error) {
  const key = discordKey ? encodeURIComponent(discordKey) : 'unknown';
  const url = `${FIREBASE_DB_URL}/errors/${key}.json`;

  const payload = {
    error: typeof error === 'string' ? error : (error.message || JSON.stringify(error)),
    stack: error.stack || null,
    time: Date.now()
  };

  try {
    console.log(`Error: ${payload.error.toString()}`)
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
  } catch (err) {
    console.error('Failed to log error:', err);
  }
}

app.get('/loginurl', async (req, res) => {
  const discordKey = req.query.discordKey;

  try {
    if (!discordKey) {
      return res.status(400).json({ error: 'Missing discordKey' });
    }
    console.log(`Prompted for login keys by <@${discordKey.toString()}>`)
    const loginUrls = API_KEYS.map((key, idx) =>
      `https://www.last.fm/api/auth?api_key=${key}&cb=${encodeURIComponent(CALLBACK_URL + `?discordKey=${discordKey}&keyNum=${idx}`)}`
    );

    res.json({ login_urls: loginUrls });
  } catch (error) {
    await logError(discordKey, error);
    res.status(500).json({ error: 'Internal server error', message: error.message });
  }
});

app.get('/callback', async (req, res) => {
  const { token, discordKey, keyNum: keyNumRaw } = req.query;
  const keyNum = parseInt(keyNumRaw, 10);

  try {
    if (!token || !discordKey || isNaN(keyNum) || keyNum < 0 || keyNum >= API_KEYS.length) {
      return res.status(400).json({ error: 'Missing or invalid token, discordKey or keyNum' });
    }

    const apiKey = API_KEYS[keyNum];
    const apiSecret = API_SECRETS[keyNum];

    const response = await callLastFmApi({ method: 'auth.getSession', api_key: apiKey, token }, apiSecret);

    if (!response.session || !response.session.key) {
      await logError(discordKey, { error: 'Failed to get session key', details: response });
      return res.status(500).json({ error: 'Failed to get session key' });
    }

    let sessionKeys = await getSessionKeys(discordKey);
    if (!sessionKeys) sessionKeys = [];

    sessionKeys[keyNum] = response.session.key;

    const updated = await updateSessionKeys(discordKey, sessionKeys);
    if (!updated) {
      await logError(discordKey, 'Failed to update session keys in DB');
      return res.status(500).json({ error: 'Failed to update session keys in DB' });
    }

    res.status(200).send('Session key updated');
  } catch (error) {
    await logError(discordKey, error);
    res.status(500).json({ error: 'Internal server error', message: error.message });
  }
});

app.post('/api/scrobble', async (req, res) => {
  const { Artist: artist, 'Track Name': track, 'Discord Key': discordKey, Times } = req.body;
  const times = parseInt(Times, 10) || 1;

  try {
    if (!artist || !track || !discordKey) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const sessionKeys = await getSessionKeys(discordKey);
    if (!sessionKeys || sessionKeys.length === 0) {
      await logError(discordKey, 'No session keys found');
      return res.status(403).json({ error: 'No session keys found' });
    }

    const now = Math.floor(Date.now() / 1000);
    const MAX_BATCH = 50;
    const errors = [];

    for (let i = 0; i < times; i += MAX_BATCH) {
      const batchCount = Math.min(MAX_BATCH, times - i);
      for (let j = 0; j < batchCount; j++) {
        const attemptIndex = (i + j) % sessionKeys.length;
        const sessionKey = sessionKeys[attemptIndex];
        
        // Skip if session key is null/undefined
        if (!sessionKey) {
          errors.push(`No session key at index ${attemptIndex}`);
          continue;
        }

        const apiKey = API_KEYS[attemptIndex];
        const apiSecret = API_SECRETS[attemptIndex];
        const timestamp = now - (i + j);
        let params = {
          method: 'track.scrobble',
          api_key: apiKey,
          sk: sessionKey,
          artist,
          track,
          timestamp: timestamp.toString(),
        };

        const scrobbleRes = await callLastFmApi(params, apiSecret);
        console.log(`Scrobble n.${j+1} (for <@${discordKey}>)`)
        console.log(`${JSON.stringify(scrobbleRes)}`)
        if (scrobbleRes.error === 29) {
          let retryCount = 0;
          let retried = false;

          while (retryCount < sessionKeys.length && !retried) {
            retryCount++;
            const nextIndex = (attemptIndex + retryCount) % sessionKeys.length;
            const nextSessionKey = sessionKeys[nextIndex];
            
            // Skip if retry session key is null/undefined
            if (!nextSessionKey) {
              continue;
            }

            const nextApiKey = API_KEYS[nextIndex];
            const nextApiSecret = API_SECRETS[nextIndex];

            const retryParams = { ...params, api_key: nextApiKey, sk: nextSessionKey };
            const retryRes = await callLastFmApi(retryParams, nextApiSecret);

            if (retryRes.error !== 29) {
              retried = true;
              if (retryRes.error) {
                errors.push(`Retry failed with error code ${retryRes.error}`);
              }
            }
          }

          if (!retried) {
            errors.push(`All session keys hit rate limit for batch starting at index ${i + j}`);
          }

        } else if (scrobbleRes.error) {
          errors.push(`API error code ${scrobbleRes.error}`);
        }
      }
    }

    // Log errors if any occurred
    if (errors.length > 0) {
      await logError(discordKey, { errors });
    }
    console.log(`Finished scrobbles for <@${discordKey}>`)
    res.json({ message: 'Scrobble complete', errors: errors.length > 0 ? errors : undefined });
  } catch (error) {
    await logError(discordKey, error);
    res.status(500).json({ error: 'Internal server error', message: error.message });
  }
});

app.all('/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Root endpoint for basic info
app.get('/', (req, res) => {
  res.json({
    service: 'ScrobblingOblin API',
    version: '1.0.0',
    endpoints: {
      '/health': 'Health check',
      '/loginurl': 'Get Last.fm login URLs',
      '/callback': 'OAuth callback',
      '/api/scrobble': 'Scrobble tracks'
    }
  });
});

// Correct catch-all for invalid routes
app.use((req, res, next) => {
  res.status(404).send('Not Found');
});

app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
