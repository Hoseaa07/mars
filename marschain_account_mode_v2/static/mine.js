let mining = false;
let totalHashes = 0;
let blocksMined = 0;
let lastHeight = 0;

let lastTickTime = null;
let lastTickHashes = 0;

function formatHashrate(hps) {
  if (hps > 1e9) return (hps / 1e9).toFixed(2) + " GH/s";
  if (hps > 1e6) return (hps / 1e6).toFixed(2) + " MH/s";
  if (hps > 1e3) return (hps / 1e3).toFixed(2) + " kH/s";
  return Math.floor(hps) + " H/s";
}

async function mineLoop() {
  if (!mining) return;

  const addrInput = document.getElementById("miner-address");
  const statusBox = document.getElementById("mine-status");
  const address = addrInput.value.trim();
  if (!address) {
    statusBox.innerHTML = "Status: <span class='font-semibold'>Isi miner address dulu.</span>";
    mining = false;
    return;
  }

  try {
    const res = await fetch("/api/mine_step", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ miner_address: address, max_tries: 50000 })
    });
    const data = await res.json();

    if (!data.ok) {
      statusBox.innerHTML = "Status: <span class='font-semibold text-rose-600 dark:text-rose-300'>Error: " + (data.error || "unknown") + "</span>";
      mining = false;
      return;
    }

    totalHashes += data.hashes || 0;
    const thisHeight = data.last_height || 0;

    if (data.found && data.block) {
      blocksMined += 1;
      lastHeight = data.block.height;
      statusBox.innerHTML = "Status: <span class='font-semibold text-emerald-700 dark:text-emerald-300'>Block " + data.block.height + " ditemukan (reward " + data.block.reward.toFixed(4) + " MARS)</span>";
    } else {
      lastHeight = thisHeight;
      statusBox.innerHTML = "Status: <span class='font-semibold text-mars-600 dark:text-mars-300'>Running…</span> Belum dapat blok, lanjut mining.";
    }

    const now = performance.now();
    if (lastTickTime === null) {
      lastTickTime = now;
      lastTickHashes = totalHashes;
    }
    const dt = (now - lastTickTime) / 1000;
    let hps = 0;
    if (dt > 0.2) {
      const dH = totalHashes - lastTickHashes;
      hps = dH / dt;
      lastTickTime = now;
      lastTickHashes = totalHashes;
    }

    document.getElementById("stat-hashes").textContent = totalHashes.toLocaleString();
    document.getElementById("stat-height").textContent = lastHeight;
    document.getElementById("stat-blocks").textContent = blocksMined;
    document.getElementById("stat-hashrate").textContent = formatHashrate(hps);

    if (mining) {
      requestAnimationFrame(mineLoop);
    }
  } catch (err) {
    console.error(err);
    statusBox.innerHTML = "Status: <span class='font-semibold text-rose-600 dark:text-rose-300'>Network error</span>";
    mining = false;
  }
}

window.addEventListener("DOMContentLoaded", () => {
  const btnStart = document.getElementById("btn-start");
  const btnStop = document.getElementById("btn-stop");

  btnStart.addEventListener("click", () => {
    if (mining) return;
    mining = true;
    document.getElementById("mine-status").innerHTML = "Status: <span class='font-semibold text-mars-600 dark:text-mars-300'>Running…</span>";
    mineLoop();
  });

  btnStop.addEventListener("click", () => {
    mining = false;
    document.getElementById("mine-status").innerHTML = "Status: <span class='font-semibold'>Stopped</span>";
  });
});
