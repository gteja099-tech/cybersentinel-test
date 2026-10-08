/* ============================================================
   CyberSentinel Test Website — script.js
   NovaTech Solutions — SPA Navigation, Forms & Interactions
   ============================================================ */

'use strict';

// ---------------------------------------------------------------
// SPA navigation
// ---------------------------------------------------------------

const PAGES = ['home', 'about', 'products', 'login', 'contact'];
const PAGE_PATHS = {
  home: '/',
  about: '/about',
  products: '/products',
  login: '/login',
  contact: '/contact',
};

/**
 * Switch the visible page and update nav active state.
 * Generates an actual HTTP request to the NovaTech backend with the destination path.
 * @param {string} pageId - one of PAGES
 */
function navigateTo(pageId) {
  if (!PAGES.includes(pageId)) {
    console.warn(`[NovaTech] Unknown page: ${pageId}`);
    return;
  }

  // Generate real request to NovaTech backend with the actual destination path (e.g. /, /about, /products, etc.)
  const targetPath = PAGE_PATHS[pageId] || (pageId === 'home' ? '/' : `/${pageId}`);
  fetch(targetPath, {
    method: 'GET',
    headers: { 'X-Requested-With': 'NovaTech-Nav' },
    cache: 'no-cache',
  }).catch(err => {
    console.debug('[NovaTech] Navigation request:', err);
  });

  // Update page visibility
  document.querySelectorAll('.page').forEach(el => el.classList.remove('active'));
  const target = document.getElementById(`page-${pageId}`);
  if (target) target.classList.add('active');

  // Update nav link highlight
  document.querySelectorAll('.nav-link').forEach(link => {
    link.classList.toggle('active', link.dataset.page === pageId);
  });

  // Close mobile nav
  document.getElementById('navLinks').classList.remove('open');
  document.getElementById('hamburger').classList.remove('open');

  // Scroll to top
  window.scrollTo({ top: 0, behavior: 'smooth' });

  // Update URL hash without triggering full reload
  history.pushState({ page: pageId }, '', `#${pageId}`);
}

// ---------------------------------------------------------------
// Bootstrap navigation from URL hash
// ---------------------------------------------------------------

function initPage() {
  const hash = window.location.hash.replace('#', '') || 'home';
  navigateTo(PAGES.includes(hash) ? hash : 'home');
}

// Handle browser back/forward
window.addEventListener('popstate', event => {
  const page = event.state?.page || 'home';
  navigateTo(page);
});

// ---------------------------------------------------------------
// Navbar scroll behaviour
// ---------------------------------------------------------------

function handleNavbarScroll() {
  const navbar = document.getElementById('navbar');
  if (window.scrollY > 10) {
    navbar.classList.add('scrolled');
  } else {
    navbar.classList.remove('scrolled');
  }
}

window.addEventListener('scroll', handleNavbarScroll, { passive: true });

// ---------------------------------------------------------------
// Hamburger / mobile nav
// ---------------------------------------------------------------

document.getElementById('hamburger').addEventListener('click', function () {
  this.classList.toggle('open');
  document.getElementById('navLinks').classList.toggle('open');
});

// ---------------------------------------------------------------
// Nav link click routing (SPA)
// ---------------------------------------------------------------

document.querySelectorAll('.nav-link').forEach(link => {
  link.addEventListener('click', function (e) {
    e.preventDefault();
    const page = this.dataset.page;
    if (page) navigateTo(page);
  });
});

document.querySelectorAll('.nav-brand').forEach(brand => {
  brand.addEventListener('click', function (e) {
    e.preventDefault();
    navigateTo('home');
  });
});

// ---------------------------------------------------------------
// Password toggle
// ---------------------------------------------------------------

function togglePassword() {
  const input  = document.getElementById('loginPassword');
  const btn    = document.querySelector('.toggle-pw');
  const isText = input.type === 'text';
  input.type   = isText ? 'password' : 'text';
  btn.textContent = isText ? 'Show' : 'Hide';
}

// ---------------------------------------------------------------
// Login form handler
// ---------------------------------------------------------------

function handleLogin(e) {
  e.preventDefault();
  const btn = document.getElementById('loginBtn');
  const msg = document.getElementById('loginMessage');
  const email    = document.getElementById('loginEmail').value.trim();
  const password = document.getElementById('loginPassword').value;

  // Simulate a loading state
  btn.textContent = 'Signing in…';
  btn.disabled = true;
  msg.className = 'login-message hidden';

  // Simulate a brief async auth check
  setTimeout(() => {
    btn.textContent = 'Sign In';
    btn.disabled = false;

    // Demo: any non-empty credentials succeed
    if (email && password.length >= 6) {
      showMessage(msg, `Welcome back, ${email.split('@')[0]}! Redirecting to your dashboard…`, 'success');
      // In production this would redirect to /dashboard
    } else {
      showMessage(msg, 'Invalid credentials. Please check your email and password.', 'error');
    }
  }, 900);
}

// ---------------------------------------------------------------
// Contact form handler
// ---------------------------------------------------------------

function handleContact(e) {
  e.preventDefault();
  const btn = document.getElementById('contactBtn');
  const msg = document.getElementById('contactMessage');

  btn.textContent = 'Sending…';
  btn.disabled = true;

  setTimeout(() => {
    btn.textContent = 'Send Message';
    btn.disabled = false;

    const form = document.getElementById('contactForm');
    showMessage(msg, '✓ Message sent! Our team will be in touch within one business day.', 'success');
    form.reset();
  }, 1000);
}

// ---------------------------------------------------------------
// Helper: show a status message
// ---------------------------------------------------------------

function showMessage(el, text, type) {
  el.textContent = text;
  el.className = `login-message ${type}`;
  // Auto-hide success messages after 6 s
  if (type === 'success') {
    setTimeout(() => { el.className = 'login-message hidden'; }, 6000);
  }
}

// ---------------------------------------------------------------
// Intersection Observer — animate cards on scroll
// ---------------------------------------------------------------

function initScrollAnimations() {
  const style = document.createElement('style');
  style.textContent = `
    .anim-target { opacity: 0; transform: translateY(24px); transition: opacity 0.5s ease, transform 0.5s ease; }
    .anim-target.visible { opacity: 1; transform: translateY(0); }
  `;
  document.head.appendChild(style);

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1 });

  const selectors = [
    '.feature-card', '.testimonial-card', '.team-card',
    '.value-item', '.pricing-card', '.product-block',
    '.office-card', '.val-card',
  ];
  document.querySelectorAll(selectors.join(',')).forEach((el, i) => {
    el.classList.add('anim-target');
    el.style.transitionDelay = `${(i % 4) * 80}ms`;
    observer.observe(el);
  });
}

// ---------------------------------------------------------------
// Navbar health ping (shows the backend is connected)
// ---------------------------------------------------------------

async function pingHealth() {
  try {
    const res  = await fetch('/health');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    console.info('[NovaTech] Backend health:', data);
  } catch (err) {
    // Silently fail — this is a frontend-only concern
    console.warn('[NovaTech] Backend health check failed:', err.message);
  }
}

// ---------------------------------------------------------------
// CyberSentinel Live Security Monitoring
// ---------------------------------------------------------------

function initLiveSecurityMonitoring() {
  const tbody = document.getElementById('predictionsTbody');
  if (!tbody) return;

  async function fetchPredictions() {
    try {
      const res = await fetch('/api/live-predictions?limit=10');
      if (!res.ok) return;
      const data = await res.json();
      
      if (data.flows && data.flows.length > 0) {
        // Clear empty state if needed
        const emptyRow = tbody.querySelector('.empty-row');
        if (emptyRow) emptyRow.remove();
        
        data.flows.forEach(flow => {
          const tr = document.createElement('tr');
          const date = new Date().toLocaleTimeString();
          
          const destPort = flow['Destination Port'] || 'N/A';
          const bytes = `${flow['Total Length of Fwd Packets'] || 0} / ${flow['Total Length of Bwd Packets'] || 0}`;
          const duration = flow['Flow Duration'] ? (flow['Flow Duration'] / 1000).toFixed(1) + 'ms' : '0ms';
          
          const conf = flow['confidence'] ? ` (${(flow['confidence']*100).toFixed(1)}%)` : '';
          const prediction = (flow['prediction'] || 'Unknown') + conf;
          const riskLevel = flow['risk_level'] || 'Unknown';
          
          const riskClass = riskLevel.toLowerCase();
          
          tr.innerHTML = `
            <td>${date}</td>
            <td>${destPort}</td>
            <td>${bytes}</td>
            <td>${duration}</td>
            <td><span class="badge-pred">${prediction}</span></td>
            <td><span class="badge-risk ${riskClass}">${riskLevel} Risk</span></td>
          `;
          
          tbody.insertBefore(tr, tbody.firstChild);
        });

        // Keep only top 15 rows
        while (tbody.children.length > 15) {
          tbody.removeChild(tbody.lastChild);
        }
      }
    } catch (err) {
      console.warn('[CyberSentinel] Polling error:', err);
    }
  }

  // Poll every 3 seconds
  setInterval(fetchPredictions, 3000);
  // Initial fetch
  fetchPredictions();
}

// ---------------------------------------------------------------
// Initialise on DOM ready
// ---------------------------------------------------------------

document.addEventListener('DOMContentLoaded', () => {
  initPage();
  initScrollAnimations();
  pingHealth();
  initLiveSecurityMonitoring();
});
