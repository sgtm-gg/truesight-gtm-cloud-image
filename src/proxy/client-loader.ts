/**
 * Client-Side Tag Loader & Integration Snippet Generators
 * Canonical implementation for @sgtm-gg/truesight-gtm-cloud-image
 * Supports both Obfuscated Shield (encrypted ingress) and Declarative transport_url modes.
 */

import { encryptXorBase64Url, DEFAULT_SECRET_KEY } from './cipher';

/**
 * Generates the obfuscated AdBlock Shield client snippet.
 * Employs client-side XOR transport encryption, intercepts /g/collect calls,
 * and rewrites script dependencies through same-origin reverse proxy endpoints.
 */
export function generateClientLoaderSnippet(
  prodUrlOrPath: string | null | undefined,
  gtmId: string,
  secretKey: string = DEFAULT_SECRET_KEY,
  metricsPath?: string | null
): string {
  const raw = (prodUrlOrPath || 'sst.example.com').trim();
  const effectiveSecret = secretKey || DEFAULT_SECRET_KEY;
  const effectiveGtmId = gtmId || 'GTM-XXXXXXX';
  const encryptedGtmId = encryptXorBase64Url(effectiveGtmId, effectiveSecret);

  const isPath = raw.startsWith('/');
  let loaderUrl: string;
  let tunnelBase: string;
  let tagBasePath: string;

  if (isPath) {
    tagBasePath = raw.replace(/\/+$/, '') || '/fps';
    const cleanMetrics = (metricsPath || '/metrics').trim().replace(/\/+$/, '') || '/metrics';
    loaderUrl = `${tagBasePath}/loader.js`;
    tunnelBase = `${cleanMetrics}/t/`;
  } else {
    const cleanUrl = raw.replace(/^https?:\/\//, '').replace(/\/+$/, '');
    tagBasePath = `https://${cleanUrl}/icefall`;
    loaderUrl = `https://${cleanUrl}/icefall/loader.js`;
    tunnelBase = `https://${cleanUrl}/icefall/t/`;
  }

  return `<!-- Google Tag Manager (Icefall Adblock Shield) -->
<script>
(function(){
var K='${effectiveSecret}';
var T='${tunnelBase}'+Math.random().toString(36).slice(2,8);
var L='${loaderUrl}';
var D='${encryptedGtmId}';
function e(s){try{var o='';for(var i=0;i<s.length;i++)o+=String.fromCharCode(s.charCodeAt(i)^K.charCodeAt(i%K.length));return btoa(o).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'')}catch(x){return''}}
function t(p,b){var c=e(p+'|||'+(b||''));if(c)_f.call(window,T+'?'+c,{method:'GET',keepalive:true,mode:'no-cors'})}
function c(u){var i=u.indexOf('/g/collect');return i!==-1?u.substring(i):null}
function r(d,cb){if(!d)return cb('');if(typeof d==='string')return cb(d);if(typeof Blob!=='undefined'&&d instanceof Blob)return d.text().then(cb).catch(function(){cb('')});if(typeof URLSearchParams!=='undefined'&&d instanceof URLSearchParams)return cb(d.toString());cb('')}
var _f=window.fetch;
window.fetch=function(i,n){var u=typeof i==='string'?i:(i&&i.url)?i.url:'';var p=c(u);if(p){var b=(n&&n.body)?n.body:(i&&typeof i!=='string'&&i.body)?i.body:null;r(b,function(s){t(p,s)});return Promise.resolve(new Response(null,{status:204}))}return _f.apply(window,arguments)};
var _b=navigator.sendBeacon;
navigator.sendBeacon=function(u,d){var p=c(u);if(p){r(d,function(s){t(p,s)});return true}return _b.apply(navigator,arguments)};
var _d=location.search.indexOf('gtm_debug=')!==-1||location.search.indexOf('gtm_preview=')!==-1;
var sd=Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype,'src');
if(sd){Object.defineProperty(HTMLScriptElement.prototype,'src',{get:function(){return sd.get.call(this)},set:function(v){try{var s=String(v),p='';if(s.indexOf('/debug/')!==-1){if(_d){var u=new URL(s,location.origin);v='${tagBasePath}'+u.pathname+u.search}}else if(s.indexOf('gtm.js')!==-1||s.indexOf('id=GTM-')!==-1)p='/gtm.js';else if((s.indexOf('gtag/js')!==-1||s.indexOf('id=G-')!==-1)&&s.indexOf('id=AW-')===-1)p='/gtag/js';else if(s.indexOf('analytics.js')!==-1)p='/analytics.js';if(p){var u=new URL(s,location.origin);if(_d&&p==='/gtm.js')v='${tagBasePath}/gtm.js'+u.search;else{var b=e(p+u.search);if(b)v='${tagBasePath}/asset?b='+b}}}catch(x){}return sd.set.call(this,v)}})}
var dl='dataLayer';window[dl]=window[dl]||[];
window[dl].push({'event':'gtm.js','gtm.start':new Date().getTime()});
var s=document.createElement('script');s.async=true;
s.src=L+'?data='+D;
var f=document.getElementsByTagName('script')[0];
f.parentNode.insertBefore(s,f);
})();
</script>
<!-- Google Tag Manager (noscript) fallback -->
<noscript><iframe src="${tagBasePath}/ns.html?id=${effectiveGtmId}" height="0" width="0" style="display:none;visibility:hidden"></iframe></noscript>
<!-- End Google Tag Manager -->`;
}

/**
 * Generates a clean, non-invasive standard GTM snippet configuring transport_url
 * for server-side tagging without prototype monkey-patching.
 * Enterprise Open-Source & Infosec Readiness.
 */
export function generateDeclarativeSnippet(
  prodUrlOrPath: string | null | undefined,
  gtmId: string
): string {
  const raw = (prodUrlOrPath || 'sst.example.com').trim();
  const effectiveGtmId = gtmId || 'GTM-XXXXXXX';

  const isPath = raw.startsWith('/');
  let servingEndpoint: string;

  if (isPath) {
    const cleanPath = raw.replace(/\/+$/, '') || '/fps';
    servingEndpoint = cleanPath;
  } else {
    const cleanUrl = raw.replace(/^https?:\/\//, '').replace(/\/+$/, '');
    servingEndpoint = `https://${cleanUrl}`;
  }

  return `<!-- Google Tag Manager (Declarative sGTM Mode - Non-Invasive) -->
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('set', 'transport_url', '${servingEndpoint}');
</script>
<script>(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':
new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],
j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src=
'${servingEndpoint}/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);
})(window,document,'script','dataLayer','${effectiveGtmId}');</script>
<noscript><iframe src="${servingEndpoint}/ns.html?id=${effectiveGtmId}" height="0" width="0" style="display:none;visibility:hidden"></iframe></noscript>
<!-- End Google Tag Manager -->`;
}
