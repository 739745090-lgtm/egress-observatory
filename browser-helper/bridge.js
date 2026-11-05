(() => {
  const publish = data => window.postMessage({channel:'egress-browser-helper',...data},location.origin);
  window.addEventListener('message', event => {
    if (event.source !== window || event.origin !== location.origin || event.data?.channel !== 'egress-browser-client') return;
    const {kind,requestId,ip} = event.data;
    if (kind === 'discover') return publish({kind:'ready',requestId,version:'1.1.0'});
    if (kind === 'cancel') { chrome.runtime.sendMessage({kind,requestId}).catch(()=>{}); return; }
    if (kind !== 'lookup' || typeof requestId !== 'string' || typeof ip !== 'string') return;
    chrome.runtime.sendMessage({kind,requestId,ip}).then(report => publish({kind:'report',requestId,report})).catch(()=>publish({kind:'error',requestId,error:'Chrome 网页查询扩展连接失败'}));
  });
  publish({kind:'ready',version:'1.1.0'});
})();
