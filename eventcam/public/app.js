const video = document.getElementById('video');
const canvas = document.getElementById('canvas');
const captureBtn = document.getElementById('capture');
const statusEl = document.getElementById('status');

let stream = null;
let capturedBlob = null;

async function startCamera() {
  if (stream) {
    stream.getTracks().forEach((track) => track.stop());
  }

  try {
    stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment' },
      audio: false
    });

    video.srcObject = stream;
    statusEl.textContent = 'Camera ready.';
  } catch (err) {
    statusEl.textContent = 'Unable to access camera.';
  }
}

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
