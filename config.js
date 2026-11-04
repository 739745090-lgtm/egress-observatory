/**
 * Public configuration. Site keys are public by design; secrets live only in the backend runtime.
 * Leave a key empty to hide that check ("未配置") without affecting the score.
 */
export const API_BASE = 'https://egress-observatory-api.reaper-f.chatgpt.site';

// Cloudflare Turnstile site key (dash.cloudflare.com → Turnstile → Add widget, hostnames below).
export const TURNSTILE_SITE_KEY = '0x4AAAAAAFzvPT8E7AAeJIDi';

// Google reCAPTCHA v3 site key (www.google.com/recaptcha/admin → v3, same hostnames).
export const RECAPTCHA_SITE_KEY = '6LcHbBAuAAAAAPZnTQiTzy68BDFtjwmBM6eqshjo';

// Hostnames to register for both keys: blackslience-reaper.github.io, 127.0.0.1, localhost
