//Replaces this frame's document with the report the page sends.
window.addEventListener('message', event => {
    if (event.source !== window.parent || typeof event.data?.html !== 'string') { return; }
    document.open();
    document.write(event.data.html);
    document.close();
});
window.parent.postMessage({ reportFrame: 'ready' }, '*');
