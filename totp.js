const overlay = document.getElementById('overlay');
const qrcodeContainer = document.getElementById('qrcode');

class Totp {

    constructor(parent, data) {

        this.parent = parent;
        this.data = data;
        this.filteredData = data.slice();

        this.filter = document.createElement("input");
        this.filter.className = "filter-box";
        this.filter.type = "text";
        this.filter.placeholder = "Filter by issuer or account...";
    
        this.shell = document.createElement('div');

        this.overlay = document.createElement('div');
        this.overlay.id = 'overlay';
        this.qrPopup = document.createElement('div');
        this.qrPopup.id = 'qrPopup';
        this.qrCode = document.createElement('div');
        this.qrCode.id = 'qrCode';
        this.qrSecret = document.createElement('div');
        this.qrPopup.appendChild(this.qrCode);
        this.qrPopup.appendChild(this.qrSecret);
        this.overlay.appendChild(this.qrPopup);

        this.parent.appendChild(this.filter);
        this.parent.appendChild(this.shell);
        this.parent.appendChild(this.overlay);

        this.init();
    }

    async init() {

        this.timeOffset = await this.syncTimeOffset();

        this.filter.addEventListener('input', (e) => {
            const term = e.target.value.trim().toLowerCase();
    
            this.filteredData = this.data.filter(entry => {
                const account = entry.account.toLowerCase();
                const issuer = entry.issuer.toLowerCase();
                return account.includes(term) || issuer.includes(term);
            });
    
            this.drawTOTPs();
            this.updateTOTPs(true);
        });
        this.filter.focus();

        this.drawTOTPs();
        this.updateTOTPs(true);

        const hideOverlay = () => {
            this.overlay.style.display = 'none';
            this.qrCode.innerHTML = "";
            this.qrSecret.innerHTML = "";
        }
        
        this.overlay.addEventListener('click', hideOverlay);
        window.addEventListener('keydown', hideOverlay);

        setInterval(() => this.updateTOTPs(), 500);
    }

    generateOtpAuthURL(entry) {
        const label = encodeURIComponent(`${entry.issuer}:${entry.account}`);
        const params = new URLSearchParams({
            secret: entry.secret.trim().replace(/=+$/, '').replace(/\s+/g, ''),
            issuer: entry.issuer,
            algorithm: entry.algorithm.replace("-", ""),
            digits: entry.digits.toString(),
            period: entry.period.toString()
        });
        return `otpauth://totp/${label}?${params.toString()}`;
    }


    base32ToBytes(base32) {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let bits = '', bytes = [];

        base32 = base32.replace(/=+$/, '').toUpperCase();
        for (const char of base32) {
            const val = alphabet.indexOf(char);
            if (val === -1) continue;
            bits += val.toString(2).padStart(5, '0');
        }
        for (let i = 0; i + 8 <= bits.length; i += 8) {
            bytes.push(parseInt(bits.slice(i, i + 8), 2));
        }
        return new Uint8Array(bytes);
    }

    async syncTimeOffset() {
        try {
            const res = await fetch("https://worldtimeapi.org/api/timezone/Etc/UTC");
            if (!res.ok) throw new Error(`HTTP error: ${res.status}`);
            const data = await res.json();
            const serverTime = new Date(data.utc_datetime).getTime();
            const localTime = Date.now();
            return serverTime - localTime;
        } catch (err) {
            console.error("Failed to sync time:", err.message);
            return 0;
        }
    }   

    async getTOTP(secret, time, algorithm, digits, period) {
        
        let counter = Math.floor(time / period);
        const keyBytes = this.base32ToBytes(secret);
        const counterBytes = new Uint8Array(8);
        
        for (let i = 7; i >= 0; i--) {
            counterBytes[i] = counter & 0xff;
            counter >>= 8;
        }

        const cryptoKey = await crypto.subtle.importKey(
            "raw",
            keyBytes,
            { name: "HMAC", hash: { name: algorithm } },  // e.g. SHA-1, SHA-256
            false,
            ["sign"]
        );

        const signature = await crypto.subtle.sign("HMAC", cryptoKey, counterBytes);
        const hmac = new Uint8Array(signature);
        const offset = hmac[hmac.length - 1] & 0xf;

        const code = (
            ((hmac[offset] & 0x7f) << 24) |
            (hmac[offset + 1] << 16) |
            (hmac[offset + 2] << 8) |
            (hmac[offset + 3])
        ) % (10 ** digits);

        return code.toString().padStart(digits, '0');
    }

    drawTOTPs() {
        
        this.shell.innerHTML = '';

        for (const entry of this.filteredData) {

            const contentWrapper = document.createElement('div');
            contentWrapper.className = 'entry-content';  

            const left = document.createElement('div');
            left.className = 'entry-left';

            const right = document.createElement('div');
            right.className = 'entry-right';

            const divIssuer = document.createElement('div');
            divIssuer.className = 'issuer';
            divIssuer.innerHTML = entry.issuer

            const divAccount = document.createElement('div');
            divAccount.className = 'account';
            divAccount.innerHTML = entry.account

            const divCode = document.createElement('div');
            divCode.className = 'code';
            divCode.textContent = entry.id

            // Click to copy
            divCode.addEventListener('click', () => {
                const code = divCode.textContent.trim();
                navigator.clipboard.writeText(code).then(() => {
                    divCode.style.opacity = '0.5';
                    setTimeout(() => divCode.style.opacity = '1', 300);
                }).catch(err => {
                    console.error('Failed to copy!', err);
                });
            });            
           
            entry.tc = new TimerCircle({ size: 25, period: entry.period });
            entry.code = divCode;

            const divQR = document.createElement('div');
            divQR.className = 'qrTrigger';
            divQR.innerHTML = '<svg width="25px" height="25px" viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg"><rect x="336" y="336" width="80" height="80" rx="8" ry="8"/><rect x="272" y="272" width="64" height="64" rx="8" ry="8"/><rect x="416" y="416" width="64" height="64" rx="8" ry="8"/><rect x="432" y="272" width="48" height="48" rx="8" ry="8"/><rect x="272" y="432" width="48" height="48" rx="8" ry="8"/><rect x="336" y="96" width="80" height="80" rx="8" ry="8"/><rect x="288" y="48" width="176" height="176" rx="16" ry="16" style="fill:none;stroke:#000000;stroke-linecap:round;stroke-linejoin:round;stroke-width:32px"/><rect x="96" y="96" width="80" height="80" rx="8" ry="8"/><rect x="48" y="48" width="176" height="176" rx="16" ry="16" style="fill:none;stroke:#000000;stroke-linecap:round;stroke-linejoin:round;stroke-width:32px"/><rect x="96" y="336" width="80" height="80" rx="8" ry="8"/><rect x="48" y="288" width="176" height="176" rx="16" ry="16" style="fill:none;stroke:#000000;stroke-linecap:round;stroke-linejoin:round;stroke-width:32px"/></svg>';
            divQR.addEventListener('click', () => {
                this.overlay.style.display = 'flex';
                this.qrCode.innerHTML = "";
                this.qrCode.appendChild(QRCode(this.generateOtpAuthURL(entry)));
                this.qrSecret.innerHTML = entry.secret;
            });

            left.appendChild(divIssuer);
            left.appendChild(divAccount);
            right.appendChild(divCode);
            right.appendChild(entry.tc.getDOMElement());
            right.appendChild(divQR);

            contentWrapper.appendChild(left);
            contentWrapper.appendChild(right);
            this.shell.appendChild(contentWrapper)
        }
    }


    async updateTOTPs(force = false) {

        let now = this.timeOffset ? Date.now() + this.timeOffset : Date.now();
        now = Math.floor(now / 1000);

        if (this.filteredData) for (const entry of this.filteredData) {

            const code = await this.getTOTP(
                entry.secret,
                now,
                entry.algorithm,
                entry.digits,
                entry.period
            )

            const secondsDone = now % entry.period;
            const secondsLeft = entry.period - secondsDone;
            entry.tc.update(secondsLeft);
            if (secondsDone == 0 || force) entry.code.innerHTML = code;
        }
    }    
}


class TimerCircle {

    constructor({ size = 30, period = 30 }) {
        this.size = size;
        this.period = period;
        this.radius = (this.size / 2) - 2;
        this.circumference = 2 * Math.PI * this.radius;

        // Create SVG namespace
        const svgNS = "http://www.w3.org/2000/svg";

        this.wrapper = document.createElement("div");
        this.wrapper.className = "circle";

        const svg = document.createElementNS(svgNS, "svg");
        svg.setAttribute("width", this.size);
        svg.setAttribute("height", this.size);

        // Background circle
        const bg = document.createElementNS(svgNS, "circle");
        bg.setAttribute("class", "background");
        bg.setAttribute("cx", this.size / 2);
        bg.setAttribute("cy", this.size / 2);
        bg.setAttribute("r", this.radius);
        svg.appendChild(bg);

        // Foreground/progress circle
        this.progressCircle = document.createElementNS(svgNS, "circle");
        this.progressCircle.setAttribute("class", "progress");
        this.progressCircle.setAttribute("cx", this.size / 2);
        this.progressCircle.setAttribute("cy", this.size / 2);
        this.progressCircle.setAttribute("r", this.radius);
        this.progressCircle.setAttribute("stroke-dasharray", this.circumference.toFixed(1));
        this.progressCircle.setAttribute("stroke-dashoffset", "0");
        svg.appendChild(this.progressCircle);

        this.wrapper.appendChild(svg);
    }

    getDOMElement() {
        return this.wrapper;
    }

    update(secondsLeft) {
        const offset = this.circumference * (1 - secondsLeft / this.period);
        this.progressCircle.setAttribute("stroke-dashoffset", offset.toFixed(1));
    }
}