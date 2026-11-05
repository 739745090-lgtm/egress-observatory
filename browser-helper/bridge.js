(() => {
  const version = chrome.runtime.getManifest().version;
  const requests = new Set();
  const publish = data => window.postMessage({channel:'egress-browser-helper',...data},location.origin);
  window.addEventListener('message', event => {
    if (event.source !== window || event.origin !== location.origin || event.data?.channel !== 'egress-browser-client') return;
    const {kind,requestId,ip,provider,skip} = event.data;
    if (kind === 'discover') return publish({kind:'ready',requestId,version});
    if (kind === 'cancel') { chrome.runtime.sendMessage({kind,requestId}).catch(()=>{}); return; }
    if (kind === 'focus' && typeof requestId === 'string' && typeof provider === 'string') { chrome.runtime.sendMessage({kind,requestId,provider}).catch(()=>{}); return; }
    if (kind !== 'lookup' || typeof requestId !== 'string' || typeof ip !== 'string') return;
    requests.add(requestId);
    chrome.runtime.sendMessage({kind,requestId,ip,skip}).then(report => {if(!report?.started){requests.delete(requestId);publish({kind:'report',requestId,report});}}).catch(()=>{requests.delete(requestId);publish({kind:'error',requestId,error:'插件连接中断，请重新加载扩展并刷新页面'});});
  });
  // Each source as soon as it answers, and pages waiting on a human check.
  chrome.runtime.onMessage.addListener(message => {
    if (message?.channel === 'egress-browser-partial' && typeof message.requestId === 'string') publish({kind:'partial',requestId:message.requestId,report:message.report});
    if (message?.channel === 'egress-browser-complete' && typeof message.requestId === 'string') {requests.delete(message.requestId);publish({kind:'report',requestId:message.requestId,report:message.report});}
  });
  publish({kind:'ready',version});
  window.addEventListener('pagehide',()=>{for(const requestId of requests)chrome.runtime.sendMessage({kind:'cancel',requestId}).catch(()=>{});});
})();
