const video = document.getElementById('video');
const canvas = document.getElementById('canvas');
const captureBtn = document.getElementById('capture');
const toggleCameraBtn = document.getElementById('toggle-camera');
const statusEl = document.getElementById('status');

let stream = null;
let capturedBlob = null;
let resolutionSet = false;
let facingMode = 'environment';

function updateFacingLabel() {
  if (!toggleCameraBtn) return;
  toggleCameraBtn.textContent = facingMode === 'user' ? 'Rear camera' : 'Selfie mode';
}

async function startCamera() {
  if (stream) {
    stream.getTracks().forEach((track) => track.stop());
  }

  try {
    const baseConstraints = { facingMode };
    const videoConstraints = [
      { facingMode, width: { ideal: 3840 }, height: { ideal: 2160 } },
      { facingMode, width: { ideal: 1920 }, height: { ideal: 1080 } },
      { facingMode, width: { ideal: 1280 }, height: { ideal: 720 } },
      baseConstraints
    ];

    let lastError = null;
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        video: baseConstraints,
        audio: false
      });
    } catch (err) {
      lastError = err;
    }

    if (stream) {
      const [track] = stream.getVideoTracks();
      const caps = track && track.getCapabilities ? track.getCapabilities() : null;
      if (caps && caps.width && caps.height) {
        try {
          await track.applyConstraints({
            width: { ideal: caps.width.max },
            height: { ideal: caps.height.max }
          });
          lastError = null;
        } catch (err) {
          lastError = err;
          stream.getTracks().forEach((t) => t.stop());
          stream = null;
        }
      }
    }

    if (!stream) {
      for (const constraints of videoConstraints) {
        try {
          stream = await navigator.mediaDevices.getUserMedia({
            video: constraints,
            audio: false
          });
          break;
        } catch (err) {
          lastError = err;
        }
      }
    }

    if (!stream && lastError) throw lastError;

    video.srcObject = stream;
    video.classList.toggle('video-mirror', facingMode === 'user');
    resolutionSet = false;
    statusEl.textContent = 'Camera ready.';
    updateFacingLabel();
  } catch (err) {
    statusEl.textContent = 'Unable to access camera.';
  }
}

video.addEventListener('loadedmetadata', () => {
  if (resolutionSet) return;
  const width = video.videoWidth;
  const height = video.videoHeight;
  if (width && height) {
    statusEl.textContent = `Camera ready. ${width}x${height}`;
    resolutionSet = true;
  }
});

captureBtn.addEventListener('click', () => {
  if (!stream) {
    statusEl.textContent = 'Camera not started.';
    return;
  }

  canvas.width = video.videoWidth;
  canvas.height = video.videoHeight;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(video, 0, 0);

  canvas.toBlob((blob) => {
    capturedBlob = blob;
    statusEl.textContent = blob ? 'Uploading...' : 'Capture failed.';
    if (blob) {
      uploadPhoto(blob);
    }
  }, 'image/jpeg', 0.9);
});

if (toggleCameraBtn) {
  toggleCameraBtn.addEventListener('click', () => {
    facingMode = facingMode === 'user' ? 'environment' : 'user';
    statusEl.textContent = 'Switching camera...';
    resolutionSet = false;
    startCamera();
  });
}

async function uploadPhoto(blob) {
  if (!blob) return;

  const data = new FormData();
  data.append('photo', blob, `event-${Date.now()}.jpg`);
  data.append('eventId', window.EVENT_ID || '');

  try {
    const response = await fetch(`/upload?event=${encodeURIComponent(window.EVENT_ID)}`, {
      method: 'POST',
      body: data
    });

    const result = await response.json();
    if (!result.ok) {
      throw new Error(result.error || 'Upload failed');
    }

    statusEl.textContent = 'Uploaded successfully.';
  } catch (err) {
    statusEl.textContent = err.message;
  }
}

startCamera();
