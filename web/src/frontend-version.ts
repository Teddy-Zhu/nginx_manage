// Capture the HTML entry resources before the router adds lazy route styles.
export const loadedFrontendEntries = [...new Set(Array.from(document.querySelectorAll(
  'script[type="module"][src], link[rel~="stylesheet"][href], link[rel~="modulepreload"][href], link[rel~="icon"][href]',
)).map((element) => new URL(element.getAttribute("src") ?? element.getAttribute("href") ?? "", window.location.href))
  .filter((url) => url.origin === window.location.origin).map((url) => url.pathname))].sort();
