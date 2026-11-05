(() => {
  const version = chrome.runtime.getManifest().version;
  const publish = data => window.postMessage({channel:'egress-browser-helper',...data},location.origin);
  window.addEventListener('message', event => {
    if (event.source !== window || event.origin !== location.origin || event.data?.channel !== 'egress-browser-client') return;
    const {kind,requestId,ip,provider} = event.data;
    if (kind === 'discover') return publish({kind:'ready',requestId,version});
    if (kind === 'cancel') { chrome.runtime.sendMessage({kind,requestId}).catch(()=>{}); return; }
    if (kind === 'focus' && typeof requestId === 'string' && typeof provider === 'string') { chrome.runtime.sendMessage({kind,requestId,provider}).catch(()=>{}); return; }
    if (kind !== 'lookup' || typeof requestId !== 'string' || typeof ip !== 'string') return;
    chrome.runtime.sendMessage({kind,requestId,ip}).then(report => publish({kind:'report',requestId,report})).catch(()=>publish({kind:'error',requestId,error:'Chrome 网页查询扩展连接失败'}));
  });
  // Each source as soon as it answers, and pages waiting on a human check.
  chrome.runtime.onMessage.addListener(message => {
    if (message?.channel === 'egress-browser-partial' && typeof message.requestId === 'string') publish({kind:'partial',requestId:message.requestId,report:message.report});
  });
  publish({kind:'ready',version});
})();
